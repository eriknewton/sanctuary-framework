//! Must match server/src/signing/business-join-lifecycle.ts and its shared vectors.
//! Pure event model, not the worker state holder. Caller authenticates checkpoint and commit events.
use super::{append_contract, records};
use serde_json::{json, Value};
pub fn initial() -> Value {
    json!({"committed":null,"provisional":null,"tombstone":null,"needs_checkpoint":true})
}
pub fn step(state: &Value, event: &Value) -> Option<Value> {
    let contract = append_contract::contract()?;
    let kind = event["type"].as_str()?;
    let fields = contract["lifecycle"][kind].as_array()?;
    let object = event.as_object()?;
    if object.len() != fields.len() + 1
        || fields
            .iter()
            .any(|k| k.as_str().map(|k| !object.contains_key(k)).unwrap_or(true))
    {
        return None;
    }
    let mut next = state.clone();
    match kind {
        "Checkpoint" => {
            let checkpoint = &event["checkpoint"];
            if !records::join_state_valid(checkpoint) || !state["provisional"].is_null() {
                return None;
            }
            if !state["tombstone"].is_null()
                && (checkpoint["anchor"]["sequence"] != state["tombstone"]["sequence"]
                    || checkpoint["anchor"]["commitment"] != state["tombstone"]["commitment"])
            {
                return None;
            }
            next["committed"] = checkpoint.clone();
            next["tombstone"] = Value::Null;
            next["needs_checkpoint"] = json!(false);
        }
        "SignAdmitted" => {
            if state["committed"].is_null()
                || state["needs_checkpoint"] != false
                || !state["provisional"].is_null()
                || !state["tombstone"].is_null()
            {
                return None;
            }
            let record = &event["record"];
            let bytes = crate::smb::jcs::encode(record).ok()?;
            let identity = append_contract::identity(bytes.as_bytes())?;
            let result = records::advance(&state["committed"], record).ok()?;
            next["provisional"] = json!({"state":result,"identity":identity,"signed":false});
            next["tombstone"] = identity;
        }
        "Signed" => {
            if state["provisional"].is_null()
                || state["provisional"]["signed"] != false
                || state["provisional"]["identity"] != event["identity"]
            {
                return None;
            }
            next["provisional"]["signed"] = json!(true);
        }
        "Committed" => {
            if state["provisional"]["signed"] != true
                || state["provisional"]["identity"] != event["identity"]
                || state["provisional"]["state"] != event["checkpoint"]
            {
                return None;
            }
            next["committed"] = state["provisional"]["state"].clone();
            next["provisional"] = Value::Null;
            next["tombstone"] = Value::Null;
        }
        "LostOrUnmatched" | "NextGrant" => {
            next["provisional"] = Value::Null;
            next["needs_checkpoint"] = json!(true)
        }
        _ => return None,
    }
    Some(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_width_refuses_before_history_advance() {
        let contract = append_contract::contract().unwrap();
        let ready = &contract["lifecycle_states"]["ready"];
        let valid = &contract["lifecycle_events"]["admit"];
        let mut invalid = valid.clone();
        invalid["record"]["outer"]["signature"] = json!("A");
        records::ADVANCE_CALLS.with(|calls| calls.set(0));
        assert!(step(ready, &invalid).is_none());
        records::ADVANCE_CALLS.with(|calls| assert_eq!(calls.get(), 0));
        assert!(step(ready, valid).is_some());
        records::ADVANCE_CALLS.with(|calls| assert_eq!(calls.get(), 1));
    }
}
