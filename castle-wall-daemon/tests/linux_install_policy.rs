//! Install admission binds explicit identity and a strictly advancing signed policy.
#![cfg(target_os = "linux")]
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use castle_wall_daemon::{
    crypto::castle_wall_signing_key_id,
    linux_install::{
        contract::IdentityConstraints,
        policy::{admit_bundle, BundleRule, PolicyBundle},
        transaction::sha256,
    },
    manifest::{
        canonical_json::canonicalize_to_bytes,
        verify::{AgentOrigin, AllowlistManifest, ManifestSignature, SignedManifest},
    },
};
use ed25519_dalek::{Signer, SigningKey};

fn fixture(generation: u64, origin: bool) -> (Vec<u8>, String) {
    let key = SigningKey::from_bytes(&[7; 32]);
    let body = castle_wall_daemon::habeas::HABEAS_LOCAL_RULE_BODY.as_bytes();
    let filename = castle_wall_daemon::manifest::rule_identity::encode_rule_filename(
        castle_wall_daemon::habeas::HABEAS_LOCAL_RULE_ID,
    )
    .unwrap();
    let entry = castle_wall_daemon::manifest::verify::ManifestRuleEntry {
        rule_id: castle_wall_daemon::habeas::HABEAS_LOCAL_RULE_ID.into(),
        file: filename.clone(),
        sha256: sha256(body),
    };
    let manifest = AllowlistManifest {
        schema_version: 1,
        fortress_id: "0123456789abcdef".into(),
        issued_at: "2026-10-01T00:00:00Z".into(),
        generation,
        agent_origin: origin.then(|| AgentOrigin {
            mode: "uid".into(),
            agent_uid: Some(60123),
            gate_uid: None,
            system_uid_allow_ceiling: 1000,
            egress_helper_signing_id: None,
            egress_helper_team_id: None,
            agent_runtime_port_range: None,
        }),
        operator_baseline: None,
        rules: vec![entry],
    };
    let signature =
        key.sign(&canonicalize_to_bytes(&serde_json::to_value(&manifest).unwrap()).unwrap());
    let signed = SignedManifest {
        manifest,
        signature: ManifestSignature {
            signature_scheme: castle_wall_daemon::constants::SIGNATURE_SCHEME_V1.into(),
            signing_key_id: castle_wall_signing_key_id(&key.verifying_key().to_bytes()).unwrap(),
            signature_b64url: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        },
    };
    let bundle = PolicyBundle {
        public_key_hex: hex::encode(key.verifying_key().to_bytes()),
        manifest_b64url: URL_SAFE_NO_PAD.encode(serde_json::to_vec(&signed).unwrap()),
        rules: vec![BundleRule {
            file: filename,
            body_b64url: URL_SAFE_NO_PAD.encode(body),
        }],
    };
    (
        serde_json::to_vec(&bundle).unwrap(),
        sha256(&key.verifying_key().to_bytes()),
    )
}
fn identity() -> IdentityConstraints<'static> {
    IdentityConstraints {
        agent_uid: 60123,
        fortress_id: "0123456789abcdef",
        service_uid: 60124,
        operator_uid: 1000,
        overflow_uid: 65534,
        system_uid_allow_ceiling: 1000,
    }
}
#[test]
fn explicit_origin_and_independent_pin_are_mandatory() {
    let (bytes, pin) = fixture(10, true);
    assert!(
        admit_bundle(&bytes, &pin, &identity()).is_ok(),
        "{:?}",
        admit_bundle(&bytes, &pin, &identity()).err()
    );
    assert!(admit_bundle(&bytes, &"0".repeat(64), &identity()).is_err());
    assert!(admit_bundle(&fixture(10, false).0, &pin, &identity()).is_err());
    let mut wrong = identity();
    wrong.agent_uid += 1;
    assert!(admit_bundle(&bytes, &pin, &wrong).is_err());
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["manifest_b64url"] = serde_json::json!(URL_SAFE_NO_PAD.encode(b"{}"));
    assert!(admit_bundle(&serde_json::to_vec(&value).unwrap(), &pin, &identity()).is_err());
}
#[test]
fn high_water_is_strict_even_for_an_identical_completed_request() {
    use castle_wall_daemon::linux_install::policy::admit_generation;
    assert!(admit_generation(10, 9, 9, false).is_ok());
    for n in [0, 8, 9] {
        assert!(admit_generation(n, 9, 8, false).is_err());
    }
    assert!(admit_generation(10, 10, 10, true).is_err());
    assert!(admit_generation(10, 9, 10, false).is_err());
    assert!(admit_generation(10, 9, 10, true).is_ok());
    assert!(admit_generation(9, 8, 10, true).is_err());
}

fn rewrite(bytes: &[u8], mutate: impl FnOnce(&mut SignedManifest), resign: bool) -> Vec<u8> {
    let mut bundle: PolicyBundle = serde_json::from_slice(bytes).unwrap();
    let mut signed: SignedManifest =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&bundle.manifest_b64url).unwrap()).unwrap();
    mutate(&mut signed);
    if resign {
        signed.signature.signature_b64url = URL_SAFE_NO_PAD.encode(
            SigningKey::from_bytes(&[7; 32])
                .sign(
                    &canonicalize_to_bytes(&serde_json::to_value(&signed.manifest).unwrap())
                        .unwrap(),
                )
                .to_bytes(),
        );
    }
    bundle.manifest_b64url = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&signed).unwrap());
    serde_json::to_vec(&bundle).unwrap()
}
#[test]
fn valid_signatures_still_bind_fortress_origin_floor_and_principal() {
    let (bytes, pin) = fixture(10, true);
    let candidates = [
        rewrite(&bytes, |s| s.manifest.fortress_id = "abcdef12".into(), true),
        rewrite(
            &bytes,
            |s| s.manifest.agent_origin.as_mut().unwrap().mode = "nat".into(),
            true,
        ),
        rewrite(
            &bytes,
            |s| s.manifest.agent_origin.as_mut().unwrap().agent_uid = Some(60125),
            true,
        ),
        rewrite(
            &bytes,
            |s| {
                s.manifest
                    .agent_origin
                    .as_mut()
                    .unwrap()
                    .system_uid_allow_ceiling = 60123
            },
            true,
        ),
        rewrite(
            &bytes,
            |s| s.manifest.agent_origin.as_mut().unwrap().gate_uid = Some(60125),
            true,
        ),
        rewrite(&bytes, |s| s.manifest.generation += 1, false),
    ];
    for bytes in candidates {
        assert!(admit_bundle(&bytes, &pin, &identity()).is_err());
    }
}
#[test]
fn bundle_quota_hashes_and_complete_rule_set_are_required() {
    let (bytes, pin) = fixture(10, true);
    let mut over = bytes.clone();
    over.resize(
        castle_wall_daemon::manifest::store::MAX_PUBLISH_BUNDLE_BYTES + 1,
        b' ',
    );
    assert!(admit_bundle(&over, &pin, &identity()).is_err());
    let mut bundle: PolicyBundle = serde_json::from_slice(&bytes).unwrap();
    let body = URL_SAFE_NO_PAD
        .decode(&bundle.rules[0].body_b64url)
        .unwrap();
    bundle.rules[0].body_b64url = URL_SAFE_NO_PAD.encode([body.as_slice(), b" "].concat());
    assert!(admit_bundle(&serde_json::to_vec(&bundle).unwrap(), &pin, &identity()).is_err());
    bundle.rules[0].body_b64url = URL_SAFE_NO_PAD.encode(body);
    bundle.rules.push(BundleRule {
        file: bundle.rules[0].file.clone(),
        body_b64url: bundle.rules[0].body_b64url.clone(),
    });
    assert!(admit_bundle(&serde_json::to_vec(&bundle).unwrap(), &pin, &identity()).is_err());
    bundle.rules.clear();
    assert!(admit_bundle(&serde_json::to_vec(&bundle).unwrap(), &pin, &identity()).is_err());
}

#[test]
fn launch_revalidates_installed_rules_pin_marker_and_committed_floor() {
    use castle_wall_daemon::{
        config::DaemonConfig,
        linux_install::{
            account::AccountStep,
            contract::ConfiguredV1,
            policy::read_installed,
            transaction::{Root, State, Transaction},
        },
    };
    let tmp = tempfile::tempdir().unwrap();
    let root = Root::open(tmp.path()).unwrap();
    let t = Transaction {
        version: 1,
        request_sha256: "a".repeat(64),
        state: State::Configured,
        agent_uid: 60123,
        service_uid: 60124,
        operator_uid: 1000,
        fortress_id: identity().fortress_id.into(),
        sanctuary_gid: Some(999),
        account_step: AccountStep::Complete,
        policy_generation: 10,
        policy_request_sha256: Some("b".repeat(64)),
        policy_complete: true,
    };
    let config = DaemonConfig::defaults_for_fortress(&t.fortress_id);
    let dir = config.policy_dir.to_str().unwrap().trim_start_matches('/');
    std::fs::create_dir_all(tmp.path().join(format!("{dir}/rules"))).unwrap();
    let (bytes, pin) = fixture(10, true);
    let admitted = admit_bundle(&bytes, &pin, &identity()).unwrap();
    root.write(
        &format!("{dir}/manifest.json"),
        &admitted.manifest_bytes,
        0o600,
    )
    .unwrap();
    root.write(&format!("{dir}/pinned.key"), &admitted.key, 0o600)
        .unwrap();
    let (name, body) = admitted.loaded.rule_files.iter().next().unwrap();
    let rule = format!("{dir}/rules/{name}");
    root.write(&rule, body, 0o600).unwrap();
    let marker = ConfiguredV1 {
        version: 1,
        agent_uid: t.agent_uid,
        fortress_id: t.fortress_id.clone(),
        command_sha256: "a".repeat(64),
        endpoints_sha256: "b".repeat(64),
        public_pin_sha256: pin,
        policy_generation: 10,
        policy_signature_b64url: admitted.loaded.manifest_signature_b64url.clone(),
        policy_sha256: sha256(&admitted.manifest_bytes),
    };
    assert!(read_installed(&root, &t, &marker).is_ok());
    root.write(&rule, b"{}", 0o600).unwrap();
    assert!(read_installed(&root, &t, &marker).is_err());
    root.write(&rule, body, 0o600).unwrap();
    root.write(&format!("{dir}/rules/extra.json"), b"{}", 0o600)
        .unwrap();
    assert!(read_installed(&root, &t, &marker).is_err());
    root.remove(&format!("{dir}/rules/extra.json")).unwrap();
    let mut changed = marker.clone();
    changed.policy_signature_b64url = URL_SAFE_NO_PAD.encode([0; 64]);
    assert!(read_installed(&root, &t, &changed).is_err());
    changed = marker.clone();
    changed.policy_generation += 1;
    assert!(read_installed(&root, &t, &changed).is_err());
    let high = format!("{dir}/.manifest-high-water.json");
    for (generation, allowed) in [(10, true), (11, false)] {
        root.write(&high,&serde_json::to_vec(&serde_json::json!({"fortress_id":t.fortress_id,"generation":generation,"manifest_signature_b64url":marker.policy_signature_b64url})).unwrap(),0o600).unwrap();
        assert_eq!(read_installed(&root, &t, &marker).is_ok(), allowed);
    }
    root.remove(&high).unwrap();
    root.write(
        &format!("{dir}/.active-policy-generation"),
        b"generation",
        0o600,
    )
    .unwrap();
    assert!(read_installed(&root, &t, &marker).is_err());
}
