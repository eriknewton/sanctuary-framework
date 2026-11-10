// fail-before-exempt: the common loader is new; predicate removal is mutation evidence.
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

// Must match checkCorpus in server/test/fixtures/business-corpus.ts.
pub const REQUIRED_CORPORA: &[&str] = &[
    "closure_vectors.json",
    "generator_vectors.json",
    "public_vectors.json",
    "record_join_vectors.json",
    "role_vectors.json",
];
const SAFE_INTEGER_MAX: u64 = (1 << 53) - 1; // Largest exactly represented JSON integer in both runtimes.
pub const MANIFEST: &str = include_str!("../../src/business_profile/vector_manifest.json");
fn keys(value: &serde_json::Map<String, Value>) -> BTreeSet<&str> {
    value.keys().map(String::as_str).collect()
}
pub fn checked(manifest: &str, name: &str, bytes: &str) -> Value {
    let manifest: Value = serde_json::from_str(manifest).expect("manifest JSON");
    let map = manifest.as_object().expect("manifest shape");
    // Only a fully shaped manifest may authorize a corpus; malformed pins cannot remove checks.
    assert_eq!(
        keys(map),
        ["version", "contract", "files"].into_iter().collect(),
        "manifest shape"
    );
    assert_eq!(manifest["version"].as_f64(), Some(1.0)); // Initial manifest version, including equivalent JSON number spelling.
    assert!(manifest["contract"].is_string(), "manifest contract");
    let files = manifest["files"].as_object().expect("manifest files");
    for entry in files.values() {
        let entry = entry.as_object().expect("manifest entry");
        assert_eq!(
            keys(entry),
            ["sha256", "cases"].into_iter().collect(),
            "manifest entry"
        );
        let hash = entry["sha256"].as_str().expect("manifest digest");
        const SHA256_HEX_LENGTH: usize = 32 * 2; // SHA-256 bytes encoded as pairs of hex digits.
        assert!(
            hash.len() == SHA256_HEX_LENGTH
                && hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "manifest digest"
        );
        for count in entry["cases"].as_object().expect("manifest cases").values() {
            assert!(
                count
                    .as_f64()
                    .is_some_and(|n| n >= 0.0 && n.fract() == 0.0 && n <= SAFE_INTEGER_MAX as f64),
                "manifest count"
            );
        }
    }
    // Continuing path: the complete required set must be pinned before any corpus can be returned.
    assert_eq!(
        keys(files),
        REQUIRED_CORPORA.iter().copied().collect(),
        "required names"
    );
    let entry = files.get(name).expect("unknown corpus");
    // Byte identity prevents a removed witness from disappearing during test collection.
    assert_eq!(
        hex::encode(Sha256::digest(bytes.as_bytes())),
        entry["sha256"].as_str().unwrap(),
        "digest"
    );
    let value: Value = serde_json::from_str(bytes).expect("corpus JSON");
    let groups: Vec<(&str, &Vec<Value>)> = if let Some(array) = value.as_array() {
        vec![("$root", array)]
    } else {
        value
            .as_object()
            .expect("corpus form")
            .iter()
            .filter_map(|(key, value)| value.as_array().map(|a| (key.as_str(), a)))
            .collect()
    };
    let counts = entry["cases"].as_object().unwrap();
    // Object groups and array roots have distinct forms, so a pin cannot silently omit a group.
    assert!(
        value.is_array() || !counts.contains_key("$root"),
        "group form"
    );
    assert_eq!(
        keys(counts),
        groups.iter().map(|(key, _)| *key).collect(),
        "group form"
    );
    for (group, values) in groups {
        // Continuing path: every pinned group retains its entire case set, even with an updated digest.
        assert_eq!(
            values.len() as f64,
            counts[group].as_f64().unwrap(),
            "count {group}"
        );
    }
    value
}
pub fn corpus(name: &str) -> Value {
    let bytes = match name {
        "closure_vectors.json" => include_str!("../../src/business_profile/closure_vectors.json"),
        "generator_vectors.json" => {
            include_str!("../../src/business_profile/generator_vectors.json")
        }
        "public_vectors.json" => include_str!("../../src/business_profile/public_vectors.json"),
        "record_join_vectors.json" => {
            include_str!("../../src/business_profile/record_join_vectors.json")
        }
        "role_vectors.json" => include_str!("../../src/business_profile/role_vectors.json"),
        _ => panic!("unknown corpus"),
    };
    checked(MANIFEST, name, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn truncated() -> String {
        let mut value = corpus("closure_vectors.json");
        value["recover"]
            .as_array_mut()
            .unwrap()
            .retain(|row| row["id"] != "recover-drain-tail-ahead-accept");
        serde_json::to_string(&value).unwrap()
    }
    #[test]
    fn equivalent_integer_number_spellings_match_the_other_runtime() {
        let manifest = MANIFEST
            .replace("\"version\": 1", "\"version\": 1.0")
            .replace("\"recover\": 7", "\"recover\": 7.0");
        assert_eq!(
            checked(
                &manifest,
                "closure_vectors.json",
                include_str!("../../src/business_profile/closure_vectors.json")
            ),
            corpus("closure_vectors.json")
        );
    }
    #[test]
    #[should_panic(expected = "digest")]
    fn truncated_custody_bytes_refuse_by_digest() {
        checked(MANIFEST, "closure_vectors.json", &truncated());
    }
    #[test]
    #[should_panic(expected = "count recover")]
    fn repinned_truncation_refuses_by_count() {
        let bytes = truncated();
        let mut manifest: Value = serde_json::from_str(MANIFEST).unwrap();
        manifest["files"]["closure_vectors.json"]["sha256"] =
            hex::encode(Sha256::digest(bytes.as_bytes())).into();
        checked(&manifest.to_string(), "closure_vectors.json", &bytes);
    }
    #[test]
    #[should_panic(expected = "required names")]
    fn missing_other_required_corpus_refuses() {
        let mut manifest: Value = serde_json::from_str(MANIFEST).unwrap();
        manifest["files"]
            .as_object_mut()
            .unwrap()
            .remove("role_vectors.json");
        checked(
            &manifest.to_string(),
            "closure_vectors.json",
            include_str!("../../src/business_profile/closure_vectors.json"),
        );
    }
    #[test]
    #[should_panic(expected = "group form")]
    fn root_array_requires_root_group() {
        let mut manifest: Value = serde_json::from_str(MANIFEST).unwrap();
        let counts = manifest["files"]["public_vectors.json"]["cases"]
            .as_object_mut()
            .unwrap();
        let count = counts.remove("$root").unwrap();
        counts.insert("cases".into(), count);
        checked(
            &manifest.to_string(),
            "public_vectors.json",
            include_str!("../../src/business_profile/public_vectors.json"),
        );
    }
    #[test]
    #[should_panic(expected = "group form")]
    fn object_corpus_rejects_root_group() {
        let mut manifest: Value = serde_json::from_str(MANIFEST).unwrap();
        manifest["files"]["closure_vectors.json"]["cases"] = serde_json::json!({"$root": 0});
        checked(
            &manifest.to_string(),
            "closure_vectors.json",
            include_str!("../../src/business_profile/closure_vectors.json"),
        );
    }
}
