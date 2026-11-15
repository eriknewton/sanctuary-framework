//! Must match server/src/signing/business-join-lifecycle.ts and its shared vectors.
//! Pure event model, not the worker state holder. Caller authenticates checkpoint and commit events.
use super::{append_contract, records};
use serde_json::{json, Value};
pub fn initial() -> Value {
    json!({"committed":null,"provisional":null,"tombstone":null,"needs_checkpoint":true})
}
fn closed(value: &Value, keys: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
    })
}
fn state_valid(state: &Value) -> bool {
    // Must match lifecycleStateValid in business-join-lifecycle.ts: only explicit null is empty, and closed wrappers bound pass-through copies.
    let identity = |value: &Value| value.is_null() || append_contract::shape("identity", value);
    closed(
        state,
        &["committed", "provisional", "tombstone", "needs_checkpoint"],
    ) && state["needs_checkpoint"].is_boolean()
        && (state["committed"].is_null() || records::join_state_valid(&state["committed"]))
        && identity(&state["tombstone"])
        && (state["provisional"].is_null()
            || (closed(&state["provisional"], &["state", "identity", "signed"])
                && records::join_state_valid(&state["provisional"]["state"])
                && identity(&state["provisional"]["identity"])
                && state["provisional"]["signed"].is_boolean()))
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
    // Must match lifecycleStep: pass-through events validate retained state before cloning.
    if !state_valid(state) {
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
    fn shared_closed_lifecycle_wrappers() {
        let rows: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/join-lifecycle-bounds.json"
        ))
        .unwrap();
        let contract = append_contract::contract().unwrap();
        for row in rows.as_array().unwrap() {
            let mut state = contract["lifecycle_states"][row["seed"].as_str().unwrap()].clone();
            let keys: Vec<_> = row["path"].as_str().unwrap().split('.').collect();
            let mut parent = &mut state;
            for key in &keys[..keys.len() - 1] {
                parent = &mut parent[*key];
            }
            let key = keys[keys.len() - 1];
            if row["remove"] == true {
                parent.as_object_mut().unwrap().remove(key);
            } else {
                parent[key] = row["value"].clone();
            }
            assert!(
                step(&state, &json!({"type":"NextGrant"})).is_none(),
                "closed lifecycle {}",
                row["id"]
            );
        }
    }

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
