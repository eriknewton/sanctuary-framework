//! Existing signed-manifest verification with install-only identity admission.
use super::{
    account,
    contract::{
        CommandV1, ConfiguredV1, EndpointsV1, IdentityConstraints, COMMAND_MAX_BYTES, COMMAND_PATH,
        CONFIGURED_PATH, DAEMON_PATH, ENDPOINTS_MAX_BYTES, ENDPOINTS_PATH, VERSION,
    },
    transaction::{checked, sha256, Root, State, Transaction, RECORD_MAX_BYTES},
    Result,
};
use crate::{
    config::DaemonConfig,
    manifest::{
        rule_identity::preflight_manifest_rule_entries,
        store::MAX_PUBLISH_BUNDLE_BYTES,
        verify::{verify_manifest_signature, verify_rule_digests, SignedManifest, VerifyResult},
        LoadedManifest,
    },
    policy::PolicySnapshot,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Public transport wrapper; manifest/rule payloads retain the existing IPC byte encoding.
/// Must match PolicyBundle in server/src/cli/linux-policy-sign.ts.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBundle {
    pub public_key_hex: String,
    pub manifest_b64url: String,
    pub rules: Vec<BundleRule>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleRule {
    pub file: String,
    pub body_b64url: String,
}
pub struct Admitted {
    pub key: Vec<u8>,
    pub manifest_bytes: Vec<u8>,
    pub loaded: LoadedManifest,
}

#[derive(Debug, thiserror::Error)]
enum InstallPolicyAdmissionError {
    #[error(
        "rule {rule_id} scope.agent_ids entry {agent_id:?}: expected {expected_form}; re-sign with the uid-<uid> form"
    )]
    MalformedAgentScope {
        rule_id: String,
        agent_id: String,
        expected_form: &'static str,
    },
    #[error(
        "rule {rule_id} scope.agent_ids entry {agent_id:?}: expected admitted uid {admitted_uid}"
    )]
    AgentScopeOutsideAdmission {
        rule_id: String,
        agent_id: String,
        admitted_uid: u32,
    },
}

fn validate_install_agent_id_scopes(
    rules: &[crate::policy::AllowlistRule],
    admitted_uid: u32,
) -> std::result::Result<(), InstallPolicyAdmissionError> {
    for rule in rules {
        // The reserved distress lane is code-derived and shape-checked here; operator-authored agent scopes use confined ids.
        if crate::habeas::is_derived_habeas_rule(rule) {
            continue;
        }
        for agent_id in &rule.scope.agent_ids {
            let Some(uid) = crate::nftables::parse_confined_agent_id(agent_id) else {
                return Err(InstallPolicyAdmissionError::MalformedAgentScope {
                    rule_id: rule.id.clone(),
                    agent_id: agent_id.clone(),
                    expected_form: crate::nftables::CONFINED_AGENT_ID_FORM,
                });
            };
            // The install profile rejects gate_uid above, so its admitted confined-id set is the agent uid singleton.
            if uid != admitted_uid {
                return Err(InstallPolicyAdmissionError::AgentScopeOutsideAdmission {
                    rule_id: rule.id.clone(),
                    agent_id: agent_id.clone(),
                    admitted_uid,
                });
            }
        }
    }
    Ok(())
}

fn validate_loaded_install_agent_id_scopes(
    loaded: &LoadedManifest,
    admitted_uid: u32,
) -> Result<PolicySnapshot> {
    let snapshot = PolicySnapshot::from_loaded_manifest(loaded)?;
    // The scope check consumes the exact typed rules the daemon will install; unreadable bytes cannot be skipped.
    validate_install_agent_id_scopes(&snapshot.rules, admitted_uid)?;
    Ok(snapshot)
}

pub fn admit_bundle(
    bytes: &[u8],
    pin: &str,
    identity: &IdentityConstraints<'_>,
) -> Result<Admitted> {
    // Match the existing broker's complete-bundle ceiling, before decoding any payload.
    if bytes.len() > MAX_PUBLISH_BUNDLE_BYTES
        || bytes.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{')
    {
        return Err("bundle shape or quota".into());
    }
    let bundle: PolicyBundle = serde_json::from_slice(bytes)?;
    let key = hex::decode(&bundle.public_key_hex)?;
    if bundle.public_key_hex != hex::encode(&key)
        || key.len() != ed25519_dalek::PUBLIC_KEY_LENGTH
        || sha256(&key) != pin
    {
        return Err("independent public pin mismatch".into());
    }
    let manifest_bytes = URL_SAFE_NO_PAD.decode(&bundle.manifest_b64url)?;
    if manifest_bytes.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
        return Err("manifest must be an object".into());
    }
    let signed: SignedManifest = serde_json::from_slice(&manifest_bytes)?;
    if verify_manifest_signature(&signed, &key) != VerifyResult::Ok {
        return Err("manifest signature refused".into());
    }
    // This signature binds F/U, not merely some signer's bytes. Omitted origin is unconfined in the legacy daemon.
    let origin = signed
        .manifest
        .agent_origin
        .as_ref()
        .ok_or("explicit agent_origin required")?;
    if origin.mode != "uid"
        || origin.agent_uid != Some(identity.agent_uid)
        || origin.gate_uid.is_some()
    {
        return Err("uid origin mismatch".into());
    }
    let relying = IdentityConstraints {
        system_uid_allow_ceiling: origin.system_uid_allow_ceiling,
        ..identity.clone()
    };
    relying.validate(
        origin.agent_uid.ok_or("agent uid absent")?,
        &signed.manifest.fortress_id,
    )?;
    if !preflight_manifest_rule_entries(&signed.manifest.rules).is_empty() {
        return Err("rule identity refused".into());
    }
    if bundle.rules.len() != signed.manifest.rules.len() {
        return Err("bundle rule set mismatch".into());
    }
    let mut rule_files = HashMap::new();
    for rule in bundle.rules {
        if !signed.manifest.rules.iter().any(|r| r.file == rule.file)
            || rule_files
                .insert(rule.file, URL_SAFE_NO_PAD.decode(rule.body_b64url)?)
                .is_some()
        {
            return Err("unexpected or duplicate rule file".into());
        }
    }
    if verify_rule_digests(&signed, &rule_files) != VerifyResult::Ok {
        return Err("rule digest refused".into());
    }
    let loaded = LoadedManifest {
        manifest_signature_b64url: signed.signature.signature_b64url.clone(),
        rule_count: signed.manifest.rules.len().try_into()?,
        signed,
        rule_files,
    };
    let _snapshot = validate_loaded_install_agent_id_scopes(&loaded, identity.agent_uid)?;
    Ok(Admitted {
        key,
        manifest_bytes,
        loaded,
    })
}
/// The daemon's equal-signature restart exception is intentionally absent here.
pub fn admit_generation(
    next: u64,
    high_water: u64,
    staged: u64,
    same_incomplete_request: bool,
) -> Result<()> {
    if next <= high_water || next < staged || (next == staged && !same_incomplete_request) {
        return Err("policy generation must advance beyond committed and staged policy".into());
    }
    Ok(())
}
// Must match ManifestHighWater in manifest/store.rs; read-only, never rewritten by the installer.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HighWater {
    fortress_id: String,
    generation: u64,
    manifest_signature_b64url: String,
}
fn high_water(root: &Root, dir: &str, fortress: &str) -> Result<Option<HighWater>> {
    match root.optional(
        &format!("{dir}/.manifest-high-water.json"),
        RECORD_MAX_BYTES,
    )? {
        None => Ok(None),
        Some(bytes) => {
            let high: HighWater = serde_json::from_slice(&bytes)?;
            if high.fortress_id != fortress
                || URL_SAFE_NO_PAD
                    .decode(&high.manifest_signature_b64url)?
                    .len()
                    != ed25519_dalek::SIGNATURE_LENGTH
            {
                return Err("invalid durable high-water".into());
            }
            Ok(Some(high))
        }
    }
}
pub fn identity(t: &Transaction, overflow: u32) -> IdentityConstraints<'_> {
    IdentityConstraints {
        agent_uid: t.agent_uid,
        fortress_id: &t.fortress_id,
        service_uid: t.service_uid,
        operator_uid: t.operator_uid,
        overflow_uid: overflow,
        system_uid_allow_ceiling: 0,
    }
}
pub fn install(root: &Root, t: &mut Transaction, bytes: &[u8], pin: &str) -> Result<()> {
    // Account completion and staged launch inputs precede every policy mutation.
    if t.account_step != account::AccountStep::Complete {
        return Err("provision accounts incomplete".into());
    }
    let command = root.read(COMMAND_PATH.trim_start_matches('/'), COMMAND_MAX_BYTES)?;
    CommandV1::parse(&command)?.validate_identity(&identity(t, account::overflow_uid()?))?;
    EndpointsV1::parse(&root.read(ENDPOINTS_PATH.trim_start_matches('/'), ENDPOINTS_MAX_BYTES)?)?;
    account::verify(root, t)?;
    let admitted = admit_bundle(bytes, pin, &identity(t, account::overflow_uid()?))?;
    let config = DaemonConfig::defaults_for_fortress(&t.fortress_id);
    let dir = config
        .policy_dir
        .to_str()
        .ok_or("policy path")?
        .trim_start_matches('/');
    let high = high_water(root, dir, &t.fortress_id)?.map_or(0, |high| high.generation);
    let request = sha256(bytes);
    let next = admitted.loaded.signed.manifest.generation;
    let mut staged = t.policy_generation;
    if let Some(raw) = root.optional(&format!("{dir}/manifest.json"), MAX_PUBLISH_BUNDLE_BYTES)? {
        let previous: SignedManifest = serde_json::from_slice(&raw)?;
        staged = staged.max(previous.manifest.generation);
    }
    admit_generation(
        next,
        high,
        staged,
        t.policy_request_sha256.as_deref() == Some(&request) && !t.policy_complete,
    )?;
    if root
        .optional(
            &format!("{dir}/.active-policy-generation"),
            RECORD_MAX_BYTES,
        )?
        .is_some()
    {
        return Err("broker-managed active generation requires repair".into());
    }
    if let Some(key) = root.optional(
        &format!("{dir}/pinned.key"),
        ed25519_dalek::PUBLIC_KEY_LENGTH,
    )? {
        if key != admitted.key {
            return Err("pin rotation is outside the install profile".into());
        }
    }
    super::command::stopped(t)?;
    // Invalidate launch authority before any staged file can differ from its recorded digest.
    root.remove(CONFIGURED_PATH.trim_start_matches('/'))?;
    t.policy_generation = next;
    t.policy_request_sha256 = Some(request);
    t.policy_complete = false;
    t.state = State::CommandStaged;
    t.save(root)?;
    root.write(&format!("{dir}/pinned.key"), &admitted.key, 0o600)?;
    root.mkdir(&format!("{dir}/rules"), 0o700)?;
    for name in root.entries(&format!("{dir}/rules"), MAX_PUBLISH_BUNDLE_BYTES)? {
        if !admitted.loaded.rule_files.contains_key(&name) {
            root.remove(&format!("{dir}/rules/{name}"))?;
        }
    }
    for (name, body) in &admitted.loaded.rule_files {
        root.write(&format!("{dir}/rules/{name}"), body, 0o600)?;
    }
    root.write(
        &format!("{dir}/manifest.json"),
        &admitted.manifest_bytes,
        0o600,
    )?;
    t.state = State::PolicyInstalled;
    t.save(root)?;
    // Read back every signed byte, then invoke the same daemon preflight that the operator ships.
    if root.read(
        &format!("{dir}/pinned.key"),
        ed25519_dalek::PUBLIC_KEY_LENGTH,
    )? != admitted.key
        || root.read(&format!("{dir}/manifest.json"), MAX_PUBLISH_BUNDLE_BYTES)?
            != admitted.manifest_bytes
    {
        return Err("policy readback mismatch".into());
    }
    for (name, body) in &admitted.loaded.rule_files {
        if &root.read(&format!("{dir}/rules/{name}"), MAX_PUBLISH_BUNDLE_BYTES)? != body {
            return Err("rule readback mismatch".into());
        }
    }
    super::command::verify_elf(root, DAEMON_PATH)?;
    checked(
        DAEMON_PATH,
        &["--preflight-manifest", "--fortress-id", &t.fortress_id],
    )?;
    super::command::stopped(t)?;
    account::verify(root, t)?;
    let command = root.read(COMMAND_PATH.trim_start_matches('/'), COMMAND_MAX_BYTES)?;
    CommandV1::parse(&command)?.validate_identity(&identity(t, account::overflow_uid()?))?;
    let endpoints = root.read(ENDPOINTS_PATH.trim_start_matches('/'), ENDPOINTS_MAX_BYTES)?;
    EndpointsV1::parse(&endpoints)?;
    let marker = ConfiguredV1 {
        version: VERSION,
        agent_uid: t.agent_uid,
        fortress_id: t.fortress_id.clone(),
        command_sha256: sha256(&command),
        endpoints_sha256: sha256(&endpoints),
        public_pin_sha256: pin.into(),
        policy_generation: next,
        policy_signature_b64url: admitted.loaded.manifest_signature_b64url,
        policy_sha256: sha256(&admitted.manifest_bytes),
    };
    marker.validate()?;
    root.write(
        CONFIGURED_PATH.trim_start_matches('/'),
        &serde_json::to_vec(&marker)?,
        0o644,
    )?;
    t.policy_complete = true;
    t.state = State::Configured;
    t.save(root)
}

/// Revalidate the complete installed set before start or enable, not only the marker's manifest digest.
pub fn read_installed(root: &Root, t: &Transaction, marker: &ConfiguredV1) -> Result<Admitted> {
    let config = DaemonConfig::defaults_for_fortress(&t.fortress_id);
    let dir = config
        .policy_dir
        .to_str()
        .ok_or("policy path")?
        .trim_start_matches('/');
    if root
        .optional(
            &format!("{dir}/.active-policy-generation"),
            RECORD_MAX_BYTES,
        )?
        .is_some()
    {
        return Err("broker-managed policy is outside this install profile".into());
    }
    let bytes = root.read(&format!("{dir}/manifest.json"), MAX_PUBLISH_BUNDLE_BYTES)?;
    let signed: SignedManifest = serde_json::from_slice(&bytes)?;
    if !preflight_manifest_rule_entries(&signed.manifest.rules).is_empty() {
        return Err("installed rule identity refused".into());
    }
    let names = root.entries(&format!("{dir}/rules"), MAX_PUBLISH_BUNDLE_BYTES)?;
    if names.len() != signed.manifest.rules.len()
        || names
            .iter()
            .any(|name| !signed.manifest.rules.iter().any(|r| r.file == *name))
    {
        return Err("installed rule set differs from manifest".into());
    }
    let mut rules = Vec::new();
    let mut total = bytes.len();
    for entry in &signed.manifest.rules {
        let body = root.read(
            &format!("{dir}/rules/{}", entry.file),
            MAX_PUBLISH_BUNDLE_BYTES,
        )?;
        total += body.len();
        if total > MAX_PUBLISH_BUNDLE_BYTES {
            return Err("installed policy quota".into());
        }
        rules.push(BundleRule {
            file: entry.file.clone(),
            body_b64url: URL_SAFE_NO_PAD.encode(body),
        });
    }
    let key = root.read(
        &format!("{dir}/pinned.key"),
        ed25519_dalek::PUBLIC_KEY_LENGTH,
    )?;
    let bundle = PolicyBundle {
        public_key_hex: hex::encode(key),
        manifest_b64url: URL_SAFE_NO_PAD.encode(&bytes),
        rules,
    };
    let admitted = admit_bundle(
        &serde_json::to_vec(&bundle)?,
        &marker.public_pin_sha256,
        &identity(t, account::overflow_uid()?),
    )?;
    let committed = high_water(root, dir, &t.fortress_id)?;
    // The relying side permits equal-generation restart only for the exact signature the daemon committed.
    let incompatible_commit = committed.is_some_and(|high| {
        high.generation > marker.policy_generation
            || (high.generation == marker.policy_generation
                && high.manifest_signature_b64url != marker.policy_signature_b64url)
    });
    if sha256(&bytes) != marker.policy_sha256
        || signed.manifest.generation != marker.policy_generation
        || signed.signature.signature_b64url != marker.policy_signature_b64url
        || incompatible_commit
    {
        return Err("installed policy differs from Configured or high-water".into());
    }
    Ok(admitted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        constants::SIGNATURE_SCHEME_V1,
        manifest::verify::{
            AllowlistManifest, ManifestRuleEntry, ManifestSignature, SignedManifest,
        },
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    const TEST_FILE: &str = "linux-explicit-ip.json";
    const TEST_RULE_ID: &str = "linux-explicit-ip";
    const TEST_FORTRESS_ID: &str = "0123456789abcdef";
    const TEST_ADMITTED_UID: u32 = 60123;

    fn rule_body(rule_id: &str, agent_id: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "id": rule_id,
            "schema_version": 1,
            "created_at": "2026-10-01T00:00:00Z",
            "match": { "ip": ["203.0.113.10"], "port": [443], "protocol": "tcp" },
            "scope": { "agent_ids": [agent_id] },
            "disposition": "allow"
        }))
        .unwrap()
    }

    fn loaded_with_body(rule_id: &str, body: Option<Vec<u8>>) -> LoadedManifest {
        let mut rule_files = HashMap::new();
        let sha = body
            .as_ref()
            .map(|bytes| sha256(bytes))
            .unwrap_or_else(|| "0".repeat(64));
        if let Some(body) = body {
            rule_files.insert(TEST_FILE.to_string(), body);
        }
        LoadedManifest {
            manifest_signature_b64url: URL_SAFE_NO_PAD.encode([0; 64]),
            rule_count: 1,
            signed: SignedManifest {
                manifest: AllowlistManifest {
                    schema_version: 1,
                    fortress_id: TEST_FORTRESS_ID.to_string(),
                    issued_at: "2026-10-01T00:00:00Z".to_string(),
                    generation: 1,
                    agent_origin: None,
                    operator_baseline: None,
                    rules: vec![ManifestRuleEntry {
                        rule_id: rule_id.to_string(),
                        file: TEST_FILE.to_string(),
                        sha256: sha,
                    }],
                },
                signature: ManifestSignature {
                    signature_scheme: SIGNATURE_SCHEME_V1.to_string(),
                    signing_key_id: "sha256:placeholder".to_string(),
                    signature_b64url: URL_SAFE_NO_PAD.encode([0; 64]),
                },
            },
            rule_files,
        }
    }

    #[test]
    fn install_scope_check_refuses_loaded_manifest_shapes_it_cannot_check() {
        let missing = validate_loaded_install_agent_id_scopes(
            &loaded_with_body(TEST_RULE_ID, None),
            TEST_ADMITTED_UID,
        )
        .unwrap_err()
        .to_string();
        assert!(missing.contains("not present"), "{missing}");

        let malformed = validate_loaded_install_agent_id_scopes(
            &loaded_with_body(TEST_RULE_ID, Some(b"{}".to_vec())),
            TEST_ADMITTED_UID,
        )
        .unwrap_err()
        .to_string();
        assert!(malformed.contains("could not be parsed"), "{malformed}");

        let mismatched = validate_loaded_install_agent_id_scopes(
            &loaded_with_body(
                TEST_RULE_ID,
                Some(rule_body(
                    "body-id",
                    &format!("{TEST_FORTRESS_ID}/uid-60123"),
                )),
            ),
            TEST_ADMITTED_UID,
        )
        .unwrap_err()
        .to_string();
        assert!(
            mismatched.contains("declares rule_id body-id"),
            "{mismatched}"
        );
    }

    #[test]
    fn install_scope_check_does_not_exempt_operator_authored_habeas_shape() {
        let rule: crate::policy::AllowlistRule = serde_json::from_value(serde_json::json!({
            "id": crate::habeas::HABEAS_LOCAL_RULE_ID,
            "schema_version": 1,
            "created_at": "2026-10-01T00:00:00Z",
            "match": { "ip": ["127.0.0.1", "::1"], "port": [crate::habeas::HABEAS_DISTRESS_PORT], "protocol": "tcp" },
            "scope": { "agent_ids": ["uid-60124"] },
            "disposition": "allow"
        }))
        .unwrap();
        assert!(!crate::habeas::is_derived_habeas_rule(&rule));
        let err = validate_install_agent_id_scopes(&[rule], TEST_ADMITTED_UID)
            .unwrap_err()
            .to_string();
        assert!(err.contains("admitted uid 60123"), "{err}");
    }
}
