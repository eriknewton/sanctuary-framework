//! Resolve the same constant expressions used by TypeScript.
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::sync::OnceLock;

// Must match server/src/smb/constants.ts and constants.json; no Rust value copy.
// QUERY_REPLY_MAX must match SURROGATE_QUERY_TIMEOUT_MS in
// server/src/credential-surrogate/constants.ts, checked by contracts.test.ts.
const SOURCE: &str = include_str!("../../../server/src/smb/constants.json");
fn source() -> &'static Value {
    static SOURCE_VALUE: OnceLock<Value> = OnceLock::new();
    SOURCE_VALUE.get_or_init(|| serde_json::from_str(SOURCE).expect("SMB constants source"))
}
fn resolve(name: &str, visiting: &mut BTreeSet<String>) -> Value {
    assert!(visiting.insert(name.into()), "SMB constant cycle");
    let entry = &source()["constants"][name];
    let result = if let Some(value) = entry.get("value") {
        value.clone()
    } else if let Some(template) = entry.get("template") {
        expand(template, visiting)
    } else {
        let expression = &entry["expression"];
        let args: Vec<u64> = expression["args"]
            .as_array()
            .expect("SMB expression")
            .iter()
            .map(|key| {
                resolve(key.as_str().unwrap(), visiting)
                    .as_u64()
                    .expect("SMB numeric constant")
            })
            .collect();
        Value::from(match expression["op"].as_str().unwrap() {
            "ref" => args[0],
            "add" => args.iter().sum(),
            "sub" => args[0] - args[1],
            "div" => args[0] / args[1],
            "floor_multiple" => args[0] / args[1] * args[1],
            "mul" => args.iter().product(),
            "base64" => args[0].div_ceil(args[1]) * args[2],
            _ => panic!("unknown SMB constant expression"),
        })
    };
    visiting.remove(name);
    result
}
// Must match template expansion in server/src/smb/constants.ts; named values stay authoritative.
fn expand(template: &Value, visiting: &mut BTreeSet<String>) -> Value {
    match template {
        Value::String(text) => {
            let mut rest = text.as_str();
            let mut out = String::new();
            while let Some((prefix, tail)) = rest.split_once("${") {
                out.push_str(prefix);
                let (key, suffix) = tail.split_once('}').expect("SMB template");
                let value = resolve(key, visiting);
                out.push_str(&match value {
                    Value::String(v) => v,
                    other => other.to_string(),
                });
                rest = suffix;
            }
            out.push_str(rest);
            Value::String(out)
        }
        Value::Array(items) => {
            Value::Array(items.iter().map(|item| expand(item, visiting)).collect())
        }
        Value::Object(items) => Value::Object(
            items
                .iter()
                .map(|(key, item)| (key.clone(), expand(item, visiting)))
                .collect(),
        ),
        other => other.clone(),
    }
}
/// Resolve the complete inventory, including expression-derived bounds.
pub fn all() -> Value {
    Value::Object(
        source()["constants"]
            .as_object()
            .unwrap()
            .keys()
            .map(|name| (name.clone(), value(name)))
            .collect::<Map<_, _>>(),
    )
}
/// Read a shared constant; malformed build-time data fails startup.
pub fn value(name: &str) -> Value {
    resolve(name, &mut BTreeSet::new())
}
/// Read a nonnegative byte, count, or time bound.
pub fn bound(name: &str) -> usize {
    usize::try_from(value(name).as_u64().expect("SMB bound")).expect("SMB usize bound")
}
