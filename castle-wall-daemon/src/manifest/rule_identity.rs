//! Cross-language rule ID and manifest filename contract.

use base64::Engine;
use std::collections::HashSet;

use super::verify::ManifestRuleEntry;

pub const RULE_ID_MAX_LENGTH: usize = 120;
pub const ENCODED_RULE_FILENAME_PREFIX: &str = "rid1_";
pub const RULE_FILENAME_SUFFIX: &str = ".json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleFilenameRelation {
    EncodedV1,
    LegacySafe,
}

pub fn validate_rule_id(value: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > RULE_ID_MAX_LENGTH {
        return Err(format!(
            "rule id must be 1..={} ASCII characters",
            RULE_ID_MAX_LENGTH
        ));
    }
    if !bytes[0].is_ascii_alphanumeric() {
        return Err("rule id must begin with an ASCII alphanumeric character".to_string());
    }
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err("rule id contains a character outside the ASCII contract".to_string());
    }
    Ok(())
}

pub fn encode_rule_filename(rule_id: &str) -> Result<String, String> {
    validate_rule_id(rule_id)?;
    Ok(format!(
        "{}{}{}",
        ENCODED_RULE_FILENAME_PREFIX,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rule_id.as_bytes()),
        RULE_FILENAME_SUFFIX
    ))
}

pub fn classify_manifest_rule_filename(
    rule_id: &str,
    filename: &str,
) -> Result<RuleFilenameRelation, String> {
    validate_rule_id(rule_id)?;
    if filename == encode_rule_filename(rule_id)? {
        return Ok(RuleFilenameRelation::EncodedV1);
    }
    if filename == format!("{}{}", rule_id, RULE_FILENAME_SUFFIX) {
        return Ok(RuleFilenameRelation::LegacySafe);
    }
    if filename.starts_with(ENCODED_RULE_FILENAME_PREFIX)
        && filename.ends_with(RULE_FILENAME_SUFFIX)
    {
        let payload = &filename
            [ENCODED_RULE_FILENAME_PREFIX.len()..filename.len() - RULE_FILENAME_SUFFIX.len()];
        if payload.is_empty()
            || !payload
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(
                "encoded-v1 rule filename has a non-canonical base64url payload".to_string(),
            );
        }
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| "encoded-v1 rule filename has an invalid base64url payload".to_string())?;
        let decoded_id = std::str::from_utf8(&decoded)
            .map_err(|_| "encoded-v1 rule filename does not decode as UTF-8".to_string())?;
        validate_rule_id(decoded_id)?;
        if encode_rule_filename(decoded_id)? != filename || decoded_id != rule_id {
            return Err("encoded-v1 rule filename does not match rule id canonically".to_string());
        }
        return Err("encoded-v1 rule filename does not match rule id".to_string());
    }
    Err("rule filename is neither encoded-v1 nor the exact legacy-safe relation".to_string())
}

/// Pure phase-one scan: validate every persisted relation before any filename
/// becomes filesystem authority.
pub fn preflight_manifest_rule_entries(entries: &[ManifestRuleEntry]) -> Vec<String> {
    let mut issues = Vec::new();
    let mut ids = HashSet::new();
    let mut filenames = HashSet::new();
    for (index, entry) in entries.iter().enumerate() {
        if !ids.insert(&entry.rule_id) {
            issues.push(format!("manifest rule {}: duplicate rule id", index));
        }
        if !filenames.insert(&entry.file) {
            issues.push(format!("manifest rule {}: duplicate rule filename", index));
        }
        if let Err(reason) = classify_manifest_rule_filename(&entry.rule_id, &entry.file) {
            issues.push(format!("manifest rule {}: {}", index, reason));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Vector {
        id: String,
        encoded_v1: String,
        legacy_safe: String,
    }
    #[derive(Deserialize)]
    struct Fixture {
        valid: Vec<Vector>,
        invalid_ids: Vec<String>,
        invalid_filenames: Vec<String>,
    }

    #[test]
    fn shared_contract_vectors_match_exactly() {
        let fixture: Fixture =
            serde_json::from_str(include_str!("../../test-vectors/rule-id-filename-v1.json"))
                .unwrap();
        for vector in fixture.valid {
            assert_eq!(encode_rule_filename(&vector.id).unwrap(), vector.encoded_v1);
            assert_eq!(
                classify_manifest_rule_filename(&vector.id, &vector.legacy_safe),
                Ok(RuleFilenameRelation::LegacySafe)
            );
        }
        for invalid in fixture.invalid_ids {
            assert!(validate_rule_id(&invalid).is_err());
        }
        for invalid in fixture.invalid_filenames {
            assert!(classify_manifest_rule_filename("a", &invalid).is_err());
        }
    }

    #[test]
    fn encodes_exact_url_safe_no_pad_filename() {
        assert_eq!(
            encode_rule_filename("curated:alpha_1.2-3").unwrap(),
            "rid1_Y3VyYXRlZDphbHBoYV8xLjItMw.json"
        );
    }

    #[test]
    fn rejects_invalid_ids_and_off_contract_relations() {
        for id in ["", ".leading", "has space", "a/b", "café", &"a".repeat(121)] {
            assert!(validate_rule_id(id).is_err(), "{id:?}");
        }
        assert!(classify_manifest_rule_filename("safe", "other.json").is_err());
        assert!(classify_manifest_rule_filename("safe", "rid1_c2FmZQ=.json").is_err());
    }
}
