//! Canonical-JSON encoder for manifest signature verification.
//!
//! Mirrors `server/src/mesh/canonical-json.ts` exactly. Object keys sorted
//! lexicographically by UTF-16 code-unit order (matches JS default sort);
//! undefined / null treatment, no whitespace, finite-number constraints.
//!
//! PR 6 will ship the cross-language vector test fixture under
//! `server/test/castle-wall/canonical-json-vectors/` that asserts
//! byte-for-byte equivalence between the TS encoder and this Rust encoder.

use serde_json::Value;

/// Errors emitted by the canonical-JSON encoder.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum CanonicalJsonError {
    #[error("non-finite number is not serializable")]
    NonFiniteNumber,
    #[error("unsupported value kind: {0}")]
    UnsupportedKind(&'static str),
}

/// Serialize a value to its canonical-JSON form (UTF-8 string).
pub fn canonicalize(value: &Value) -> Result<String, CanonicalJsonError> {
    let mut out = String::new();
    encode(value, &mut out)?;
    Ok(out)
}

/// UTF-8 bytes of the canonical JSON.
pub fn canonicalize_to_bytes(value: &Value) -> Result<Vec<u8>, CanonicalJsonError> {
    Ok(canonicalize(value)?.into_bytes())
}

fn encode(value: &Value, out: &mut String) -> Result<(), CanonicalJsonError> {
    match value {
        Value::Null => {
            out.push_str("null");
            Ok(())
        }
        Value::Bool(true) => {
            out.push_str("true");
            Ok(())
        }
        Value::Bool(false) => {
            out.push_str("false");
            Ok(())
        }
        Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                if !f.is_finite() {
                    return Err(CanonicalJsonError::NonFiniteNumber);
                }
            }
            out.push_str(&n.to_string());
            Ok(())
        }
        Value::String(s) => {
            // Safety: `serde_json::to_string` on a Rust `String`/`&str` is
            // infallible. Strings have no Serialize implementation that can
            // return Err and no numeric or IO surface to fail on. A panic
            // here would mean the serde_json contract has changed and the
            // canonical-form invariant (cross-language byte-match with
            // server/src/mesh/canonical-json.ts) is broken; fail-fast is
            // the correct response.
            out.push_str(&serde_json::to_string(s).expect("serialize str"));
            Ok(())
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                encode(item, out)?;
            }
            out.push(']');
            Ok(())
        }
        Value::Object(map) => {
            // serde_json::Map preserves insertion order; canonical form requires
            // sort by code-unit (UTF-16) order to match the JS encoder.
            // For ASCII keys (which is the case in every manifest field) this
            // matches byte-wise sort. Non-ASCII keys are not used in v1
            // manifests; PR 6 will add a vector test that exercises non-ASCII.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| {
                let a_units: Vec<u16> = a.encode_utf16().collect();
                let b_units: Vec<u16> = b.encode_utf16().collect();
                a_units.cmp(&b_units)
            });
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                // Safety: same infallibility argument as the Value::String
                // arm above; `serde_json::to_string` on `&str` cannot fail.
                out.push_str(&serde_json::to_string(k.as_str()).expect("serialize key"));
                out.push(':');
                // Safety: `keys` was built from `map.keys().collect()` and
                // sorted in place, with no intervening mutation of `map`;
                // every key in `keys` is therefore present in `map` and
                // `map.get(*k)` cannot return None.
                encode(map.get(*k).expect("key present"), out)?;
            }
            out.push('}');
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn primitives_serialize_canonically() {
        assert_eq!(canonicalize(&json!(null)).unwrap(), "null");
        assert_eq!(canonicalize(&json!(true)).unwrap(), "true");
        assert_eq!(canonicalize(&json!(false)).unwrap(), "false");
        assert_eq!(canonicalize(&json!(42)).unwrap(), "42");
        assert_eq!(canonicalize(&json!("hi")).unwrap(), "\"hi\"");
    }

    #[test]
    fn object_keys_are_sorted_lexicographically() {
        let v = json!({ "b": 1, "a": 2, "c": 3 });
        assert_eq!(canonicalize(&v).unwrap(), "{\"a\":2,\"b\":1,\"c\":3}");
    }

    #[test]
    fn nested_objects_recursively_canonicalize() {
        let v = json!({ "outer": { "z": 1, "a": 2 }, "first": [3, 1, 2] });
        assert_eq!(
            canonicalize(&v).unwrap(),
            "{\"first\":[3,1,2],\"outer\":{\"a\":2,\"z\":1}}"
        );
    }

    #[test]
    fn no_whitespace_in_output() {
        let v = json!({ "x": [1, 2, 3], "y": "z" });
        let out = canonicalize(&v).unwrap();
        assert!(!out.contains(' '));
        assert!(!out.contains('\n'));
    }

    #[test]
    fn ts_canonical_form_byte_match() {
        // Reference output from the TypeScript canonicalize() for the same input.
        // Ensures the Rust encoder matches the TS contract for a manifest-shaped
        // value. PR 6 expands this with the full vector fixture.
        let manifest = json!({
            "schema_version": 1,
            "fortress_id": "deadbeef",
            "issued_at": "2026-05-04T00:00:00Z",
            "rules": [
                { "rule_id": "uuid-1", "file": "rule-1.json", "sha256": "aa" },
                { "rule_id": "uuid-2", "file": "rule-2.json", "sha256": "bb" }
            ]
        });
        let expected = "{\"fortress_id\":\"deadbeef\",\"issued_at\":\"2026-05-04T00:00:00Z\",\"rules\":[{\"file\":\"rule-1.json\",\"rule_id\":\"uuid-1\",\"sha256\":\"aa\"},{\"file\":\"rule-2.json\",\"rule_id\":\"uuid-2\",\"sha256\":\"bb\"}],\"schema_version\":1}";
        assert_eq!(canonicalize(&manifest).unwrap(), expected);
    }
}
