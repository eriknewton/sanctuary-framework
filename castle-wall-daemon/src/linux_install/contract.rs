//! Install-only wire contracts shared by the provisioner and launcher.
//!
//! Parsing proves shape and bounds only, never custody, signature verification,
//! host identity, READY, or live enforcement. Consumers must verify those facts
//! against their own trusted observations before publishing or using Configured.
//! P1 schema payloads and P3 consumers must match these definitions; changes to
//! this contract require coordinated consumer updates, not copied parsers.

use std::{collections::BTreeMap, net::IpAddr, path::PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize};

use crate::{config::validate_fortress_id, crypto::parse_strict_verifying_key};

// Fixed policy choices from the install contract, not measured runtime guarantees.
pub const VERSION: u32 = 1;
pub const KIB: usize = 1024;
pub const MIB: usize = KIB * KIB;
pub const COMMAND_MAX_BYTES: usize = 16 * KIB;
pub const ENDPOINTS_MAX_BYTES: usize = 8 * KIB;
pub const CONFIGURED_MAX_BYTES: usize = 4 * KIB;
pub const ARGV_MAX_ENTRIES: usize = 64;
pub const STRING_MAX_BYTES: usize = KIB;
pub const ENV_MAX_ENTRIES: usize = 16;
pub const ENV_ALLOWED_KEYS: [&str; 3] = ["LANG", "LC_ALL", "TZ"];
pub const RESOURCE_PROFILE: &str = "bounded-v1";
pub const IP_MAX_BYTES: usize = 45; // Longest IPv6 literal with embedded IPv4.
pub const ENDPOINT_COUNT: usize = 6; // Two families times three role/protocol pairs.
pub const ATTEMPTS_PER_ENDPOINT: u8 = 3;
pub const ATTEMPTS_PER_ACTIVATION: usize = ENDPOINT_COUNT * ATTEMPTS_PER_ENDPOINT as usize;
pub const INITIAL_DELAY_MS: u32 = 60_000;
pub const ATTEMPT_TIMEOUT_MS: u32 = 3_000;
pub const MAX_RESPONSE_BYTES: u32 = 256;
pub const OBSERVATION_MAX_BYTES: usize = 64 * KIB;
pub const WORKSPACE_MAX_BYTES: usize = 64 * MIB;
pub const WORKSPACE_MAX_INODES: usize = 4096;
pub const MEMORY_MAX_BYTES: usize = 512 * MIB;
pub const TASKS_MAX: usize = 64;
pub const CORE_MAX_BYTES: usize = 0;
pub const AMAX: usize = 1024;
pub const PMAX: usize = 16;
pub const EMAX: usize = 4096;
pub const CMAX: usize = 4 * MIB;
pub const PLANNED_WAL_MAX_BYTES: usize = AMAX * PMAX * EMAX + CMAX;
pub const SHA256_HEX_BYTES: usize = 32 * 2; // Two hex digits per SHA-256 byte.
pub const PUBLIC_KEY_HEX_BYTES: usize = ed25519_dalek::PUBLIC_KEY_LENGTH * 2;
pub const SIGNATURE_B64URL_BYTES: usize = (ed25519_dalek::SIGNATURE_LENGTH * 8).div_ceil(6);

pub const DAEMON_PATH: &str = "/usr/local/libexec/sanctuary/castle-wall-daemon";
pub const CLI_PATH: &str = "/usr/sbin/sanctuary-linux";
pub const LAUNCHER_PATH: &str = "/usr/local/libexec/sanctuary/protected-agent-v1";
pub const STANDIN_PATH: &str = "/usr/local/libexec/sanctuary/network-agent-standin";
pub const ENV_PATH: &str = "/etc/sanctuary/castle-wall.env";
pub const COMMAND_PATH: &str = "/etc/sanctuary/agent/command-v1.json";
pub const ENDPOINTS_PATH: &str = "/etc/sanctuary/agent/endpoints.json";
pub const CONFIGURED_PATH: &str = "/etc/sanctuary/agent/configured-v1.json";
pub const WORKSPACE_PATH: &str = "/var/lib/sanctuary-agent-workspace";
pub const WORKSPACE_MOUNT_UNIT: &str = "var-lib-sanctuary\\x2dagent\\x2dworkspace.mount";

#[derive(Debug, thiserror::Error)]
pub enum ContractError {
    #[error("encoded record exceeds its byte quota")]
    Oversize,
    #[error("malformed contract JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid contract field: {0}")]
    Invalid(&'static str),
}

type Result<T> = std::result::Result<T, ContractError>;

fn require(condition: bool, field: &'static str) -> Result<()> {
    // Invalid or absent evidence cannot become an admitted contract value.
    if !condition {
        return Err(ContractError::Invalid(field));
    }
    Ok(())
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8], limit: usize) -> Result<T> {
    // Bound allocation and parse work before serde sees attacker-influenced bytes.
    if bytes.len() > limit {
        return Err(ContractError::Oversize);
    }
    Ok(serde_json::from_slice::<JsonObject<T>>(bytes)?.0)
}

// Serde derives also accept positional arrays; these wire records require objects.
struct JsonObject<T>(T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for JsonObject<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct ObjectVisitor<T>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for ObjectVisitor<T> {
            type Value = JsonObject<T>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                map: M,
            ) -> std::result::Result<Self::Value, M::Error> {
                T::deserialize(serde::de::value::MapAccessDeserializer::new(map)).map(JsonObject)
            }
        }
        // Object-only admission preserves duplicate detection in the typed visitor.
        d.deserialize_map(ObjectVisitor(std::marker::PhantomData))
    }
}

fn deserialize_endpoints<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<[Endpoint; ENDPOINT_COUNT], D::Error> {
    <[JsonObject<Endpoint>; ENDPOINT_COUNT]>::deserialize(d)
        .map(|entries| entries.map(|entry| entry.0))
}

fn text_valid(value: &str) -> bool {
    value.len() <= STRING_MAX_BYTES && !value.contains('\0')
}

fn lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn identity_shape(uid: u32, fortress: &str) -> Result<()> {
    require(uid != 0 && uid != u32::MAX, "agent_uid")?;
    // Must match the shared grammar used by the daemon/gate in config.rs.
    require(validate_fortress_id(fortress).is_ok(), "fortress_id")
}

/// Trusted identity observations supplied by provision/launch, never by input JSON.
#[derive(Debug, Clone)]
pub struct IdentityConstraints<'a> {
    pub agent_uid: u32,
    pub fortress_id: &'a str,
    pub service_uid: u32,
    pub operator_uid: u32,
    pub overflow_uid: u32,
    pub system_uid_allow_ceiling: u32,
}

impl IdentityConstraints<'_> {
    /// Check U/F and signed floor against the relying party's observed exclusions.
    pub fn validate(&self, uid: u32, fortress: &str) -> Result<()> {
        identity_shape(uid, fortress)?;
        // JSON must not select which principal receives the configured authority.
        require(
            uid == self.agent_uid && fortress == self.fortress_id,
            "configured identity",
        )?;
        require(uid > self.system_uid_allow_ceiling, "signed uid floor")?;
        require(
            ![self.service_uid, self.operator_uid, self.overflow_uid].contains(&uid),
            "excluded uid",
        )
    }
}

/// Literal exec input; argv excludes argv[0]. No inherited environment is implied.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommandV1 {
    pub version: u32,
    pub agent_uid: u32,
    pub fortress_id: String,
    pub executable: String,
    pub argv: Vec<String>,
    #[serde(deserialize_with = "deserialize_env")]
    pub env: BTreeMap<String, String>,
    pub resource_profile: String,
}

// A map's usual deserializer overwrites duplicate keys, so visit entries directly.
fn deserialize_env<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<BTreeMap<String, String>, D::Error> {
    struct EnvVisitor;
    impl<'de> serde::de::Visitor<'de> for EnvVisitor {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a bounded environment object with unique keys")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> std::result::Result<Self::Value, M::Error> {
            let mut result = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, String>()? {
                // Duplicate values cannot erase evidence of an ambiguous environment.
                if result.len() >= ENV_MAX_ENTRIES || result.insert(key, value).is_some() {
                    return Err(M::Error::custom("environment quota or duplicate key"));
                }
            }
            Ok(result)
        }
    }
    d.deserialize_map(EnvVisitor)
}

impl CommandV1 {
    /// Parse a bounded record; follow with validate_identity and executable custody checks.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode(bytes, COMMAND_MAX_BYTES)?;
        value.validate()?;
        Ok(value)
    }

    /// Validate typed input too; serialization must still fit the encoded file quota.
    pub fn validate(&self) -> Result<()> {
        require(self.version == VERSION, "version")?;
        identity_shape(self.agent_uid, &self.fortress_id)?;
        // Reject lexical aliases before the later descriptor-based custody checks.
        require(
            text_valid(&self.executable)
                && self.executable.starts_with('/')
                && self.executable[1..]
                    .split('/')
                    .all(|c| !c.is_empty() && c != "." && c != ".."),
            "executable",
        )?;
        require(self.argv.len() <= ARGV_MAX_ENTRIES, "argv count")?;
        require(self.argv.iter().all(|s| text_valid(s)), "argv bytes")?;
        require(self.env.len() <= ENV_MAX_ENTRIES, "env count")?;
        // The closed list excludes loader controls and user-supplied HOME.
        require(
            self.env
                .iter()
                .all(|(k, v)| ENV_ALLOWED_KEYS.contains(&k.as_str()) && text_valid(v)),
            "env",
        )?;
        require(
            self.resource_profile == RESOURCE_PROFILE,
            "resource_profile",
        )?;
        require(
            serde_json::to_vec(self)?.len() <= COMMAND_MAX_BYTES,
            "command encoded bytes",
        )
    }

    pub fn validate_identity(&self, identity: &IdentityConstraints<'_>) -> Result<()> {
        identity.validate(self.agent_uid, &self.fortress_id)
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    Ipv4,
    Ipv6,
}
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Deny,
    Allow,
}
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

/// Explicit nullable field; deserialize_with prevents a missing Option from defaulting to None.
fn required_nullable<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<String>, D::Error> {
    Option::<String>::deserialize(d)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub family: Family,
    pub role: Role,
    pub protocol: Protocol,
    pub ip: String,
    pub port: u16,
    pub attempts: u8,
    #[serde(deserialize_with = "required_nullable")]
    pub response_public_key_hex: Option<String>,
}

/// Purpose is chosen by the caller, never by the installed descriptor.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum EndpointPurpose {
    Product,
    FaultInstrument,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EndpointsV1 {
    pub version: u32,
    pub initial_delay_ms: u32,
    pub attempt_timeout_ms: u32,
    pub max_response_bytes: u32,
    #[serde(deserialize_with = "deserialize_endpoints")]
    pub endpoints: [Endpoint; ENDPOINT_COUNT],
}

pub const ENDPOINT_ORDER: [(Family, Role, Protocol); ENDPOINT_COUNT] = [
    (Family::Ipv4, Role::Deny, Protocol::Tcp),
    (Family::Ipv4, Role::Deny, Protocol::Udp),
    (Family::Ipv4, Role::Allow, Protocol::Tcp),
    (Family::Ipv6, Role::Deny, Protocol::Tcp),
    (Family::Ipv6, Role::Deny, Protocol::Udp),
    (Family::Ipv6, Role::Allow, Protocol::Tcp),
];

impl EndpointsV1 {
    /// Product parsing cannot accept a reduced fault-instrument schedule.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        Self::parse_for(bytes, EndpointPurpose::Product)
    }

    pub fn parse_for(bytes: &[u8], purpose: EndpointPurpose) -> Result<Self> {
        let value: Self = decode(bytes, ENDPOINTS_MAX_BYTES)?;
        value.validate(purpose)?;
        Ok(value)
    }

    pub fn validate(&self, purpose: EndpointPurpose) -> Result<()> {
        require(self.version == VERSION, "version")?;
        require(
            self.initial_delay_ms == INITIAL_DELAY_MS,
            "initial_delay_ms",
        )?;
        require(
            self.attempt_timeout_ms == ATTEMPT_TIMEOUT_MS,
            "attempt_timeout_ms",
        )?;
        require(
            self.max_response_bytes == MAX_RESPONSE_BYTES,
            "max_response_bytes",
        )?;
        let mut tuples = Vec::with_capacity(ENDPOINT_COUNT);
        let mut attempts = 0;
        for (endpoint, order) in self.endpoints.iter().zip(ENDPOINT_ORDER) {
            // A fixed order fixes the schedule and forbids new role/protocol combinations.
            require(
                (endpoint.family, endpoint.role, endpoint.protocol) == order,
                "endpoint order",
            )?;
            require(
                !endpoint.ip.is_empty()
                    && endpoint.ip.len() <= IP_MAX_BYTES
                    && endpoint.ip.is_ascii(),
                "ip bytes",
            )?;
            let ip: IpAddr = endpoint
                .ip
                .parse()
                .map_err(|_| ContractError::Invalid("ip literal"))?;
            require(
                matches!(
                    (endpoint.family, ip),
                    (Family::Ipv4, IpAddr::V4(_)) | (Family::Ipv6, IpAddr::V6(_))
                ),
                "ip family",
            )?;
            require(endpoint.port != 0, "port")?;
            let tuple = (endpoint.protocol, ip, endpoint.port);
            // Compare parsed addresses so alternate IPv6 spellings cannot alias a tuple.
            require(!tuples.contains(&tuple), "duplicate endpoint tuple")?;
            tuples.push(tuple);
            require(
                endpoint.attempts <= ATTEMPTS_PER_ENDPOINT,
                "attempts ceiling",
            )?;
            require(
                purpose != EndpointPurpose::Product || endpoint.attempts == ATTEMPTS_PER_ENDPOINT,
                "product attempts",
            )?;
            attempts += usize::from(endpoint.attempts);
            match (endpoint.role, &endpoint.response_public_key_hex) {
                (Role::Deny, None) => {}
                (Role::Allow, Some(key)) => {
                    require(
                        lowercase_hex(key, PUBLIC_KEY_HEX_BYTES),
                        "response key encoding",
                    )?;
                    let raw =
                        hex::decode(key).map_err(|_| ContractError::Invalid("response key"))?;
                    // Public bytes must be a valid authority key before response verification.
                    require(parse_strict_verifying_key(&raw).is_ok(), "response key")?;
                }
                _ => return Err(ContractError::Invalid("response key role")),
            }
        }
        require(
            (1..=ATTEMPTS_PER_ACTIVATION).contains(&attempts),
            "total attempts",
        )?;
        // Fixed field bounds put typed serialization below the file quota; decode
        // separately bounds the original bytes, including escapes and whitespace.
        Ok(())
    }
}

/// Root-published Configured binding. Digests are lowercase SHA-256 hex of the
/// exact installed bytes. The signature is the manifest's existing base64url
/// Ed25519 signature. Parsing does not verify that signature or authorize launch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConfiguredV1 {
    pub version: u32,
    pub agent_uid: u32,
    pub fortress_id: String,
    pub command_sha256: String,
    pub endpoints_sha256: String,
    pub public_pin_sha256: String,
    pub policy_generation: u64,
    pub policy_signature_b64url: String,
    pub policy_sha256: String,
}

impl ConfiguredV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode(bytes, CONFIGURED_MAX_BYTES)?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<()> {
        require(self.version == VERSION, "version")?;
        identity_shape(self.agent_uid, &self.fortress_id)?;
        for digest in [
            &self.command_sha256,
            &self.endpoints_sha256,
            &self.public_pin_sha256,
            &self.policy_sha256,
        ] {
            require(lowercase_hex(digest, SHA256_HEX_BYTES), "sha256")?;
        }
        require(
            self.policy_signature_b64url.len() == SIGNATURE_B64URL_BYTES,
            "policy signature bytes",
        )?;
        // Match signature_b64url in manifest/verify.rs; this checks encoding, not authenticity.
        let signature = URL_SAFE_NO_PAD
            .decode(&self.policy_signature_b64url)
            .map_err(|_| ContractError::Invalid("policy signature"))?;
        // Canonical unpadded base64url of the checked encoded length is exactly
        // SIGNATURE_LENGTH bytes; authenticity belongs to the policy verifier.
        debug_assert_eq!(signature.len(), ed25519_dalek::SIGNATURE_LENGTH);
        Ok(())
    }

    pub fn validate_identity(&self, identity: &IdentityConstraints<'_>) -> Result<()> {
        identity.validate(self.agent_uid, &self.fortress_id)
    }
}

/// Policy paths come from the daemon's own layout, so installation cannot drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyPaths {
    pub directory: PathBuf,
    pub pin: PathBuf,
    pub manifest: PathBuf,
    pub rules: PathBuf,
}

impl PolicyPaths {
    pub fn for_fortress(fortress_id: &str) -> Result<Self> {
        require(validate_fortress_id(fortress_id).is_ok(), "fortress_id")?;
        let config = crate::config::DaemonConfig::defaults_for_fortress(fortress_id);
        // Must match ManifestStore's manifest.json/rules layout in manifest/store.rs.
        Ok(Self {
            manifest: config.policy_dir.join("manifest.json"),
            rules: config.policy_dir.join("rules"),
            directory: config.policy_dir,
            pin: config.pinned_public_key_path,
        })
    }
}

#[cfg(test)]
mod tests {
    // These tests prove contract admission and bounded parsing, not installed enforcement.
    use super::*;
    use serde_json::{json, Value};

    type ValueParser = fn(&Value) -> bool;
    type BytesParser = fn(&[u8]) -> bool;

    const TEST_UID: u32 = 60123;
    const TEST_FORTRESS: &str = "0123456789abcdef";
    const TEST_KEY: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    fn command() -> Value {
        json!({"version": VERSION, "agent_uid": TEST_UID, "fortress_id": TEST_FORTRESS,
            "executable": STANDIN_PATH, "argv": ["--endpoints", ENDPOINTS_PATH],
            "env": {}, "resource_profile": RESOURCE_PROFILE})
    }

    fn endpoints() -> Value {
        let entries: Vec<_> = ENDPOINT_ORDER.iter().map(|(family, role, protocol)| {
            let ip = match (family, role) {
                (Family::Ipv4, Role::Deny) => "192.0.2.10",
                (Family::Ipv4, Role::Allow) => "192.0.2.11",
                (Family::Ipv6, Role::Deny) => "2001:db8::10",
                (Family::Ipv6, Role::Allow) => "2001:db8::11",
            };
            json!({"family": family, "role": role, "protocol": protocol, "ip": ip,
                "port": 41001, "attempts": ATTEMPTS_PER_ENDPOINT,
                "response_public_key_hex": if *role == Role::Allow { Some(TEST_KEY) } else { None }})
        }).collect();
        json!({"version": VERSION, "initial_delay_ms": INITIAL_DELAY_MS,
            "attempt_timeout_ms": ATTEMPT_TIMEOUT_MS, "max_response_bytes": MAX_RESPONSE_BYTES,
            "endpoints": entries})
    }

    fn configured() -> Value {
        json!({"version": VERSION, "agent_uid": TEST_UID, "fortress_id": TEST_FORTRESS,
            "command_sha256": "a".repeat(SHA256_HEX_BYTES),
            "endpoints_sha256": "b".repeat(SHA256_HEX_BYTES),
            "public_pin_sha256": "c".repeat(SHA256_HEX_BYTES),
            "policy_generation": 1, "policy_signature_b64url": URL_SAFE_NO_PAD.encode([0; ed25519_dalek::SIGNATURE_LENGTH]),
            "policy_sha256": "d".repeat(SHA256_HEX_BYTES)})
    }

    fn bytes(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).unwrap()
    }
    fn cmd_ok(value: &Value) -> bool {
        CommandV1::parse(&bytes(value)).is_ok()
    }
    fn ep_ok(value: &Value) -> bool {
        EndpointsV1::parse(&bytes(value)).is_ok()
    }
    fn marker_ok(value: &Value) -> bool {
        ConfiguredV1::parse(&bytes(value)).is_ok()
    }

    #[test]
    fn valid_roundtrips_and_file_ceilings() {
        let fixtures: [(Value, usize, BytesParser); 3] = [
            (command(), COMMAND_MAX_BYTES, |b| {
                CommandV1::parse(b).is_ok()
            }),
            (endpoints(), ENDPOINTS_MAX_BYTES, |b| {
                EndpointsV1::parse(b).is_ok()
            }),
            (configured(), CONFIGURED_MAX_BYTES, |b| {
                ConfiguredV1::parse(b).is_ok()
            }),
        ];
        for (value, limit, parse) in fixtures {
            let mut encoded = bytes(&value);
            assert!(parse(&encoded));
            encoded.resize(limit, b' ');
            assert!(parse(&encoded), "exact byte ceiling");
            encoded.push(b' ');
            assert!(!parse(&encoded), "one over byte ceiling");
            for bad in [
                b"".as_slice(),
                b"null",
                b"[]",
                b"{}",
                b"{",
                b"\xff",
                b"{} {}",
            ] {
                assert!(!parse(bad));
            }
        }
    }

    #[test]
    fn required_unknown_duplicate_and_wrong_type_fields() {
        let fixtures: [(Value, ValueParser, BytesParser); 3] = [
            (command(), cmd_ok, |b| CommandV1::parse(b).is_ok()),
            (endpoints(), ep_ok, |b| EndpointsV1::parse(b).is_ok()),
            (configured(), marker_ok, |b| ConfiguredV1::parse(b).is_ok()),
        ];
        for (value, parse, parse_bytes) in fixtures {
            let object = value.as_object().unwrap();
            for key in object.keys() {
                let mut missing = value.clone();
                missing.as_object_mut().unwrap().remove(key);
                assert!(!parse(&missing), "missing {key}");
                let mut wrong = value.clone();
                wrong[key] = json!(true);
                assert!(!parse(&wrong), "wrong type {key}");
                let duplicate = format!(
                    "{{{key:?}:{},{}",
                    object[key],
                    &String::from_utf8(bytes(&value)).unwrap()[1..]
                );
                assert!(!parse_bytes(duplicate.as_bytes()), "duplicate {key}");
            }
            let mut unknown = value.clone();
            unknown["extra"] = json!(true);
            assert!(!parse(&unknown));
            for invalid in [
                json!(0),
                json!(2),
                json!(1.0),
                json!("1"),
                json!(null),
                json!(-1),
            ] {
                let mut wrong = value.clone();
                wrong["version"] = invalid;
                assert!(!parse(&wrong));
            }
        }
        for key in endpoints()["endpoints"][0].as_object().unwrap().keys() {
            let mut value = endpoints();
            value["endpoints"][0].as_object_mut().unwrap().remove(key);
            assert!(!ep_ok(&value), "missing endpoint {key}");
            let mut value = endpoints();
            value["endpoints"][0][key] = json!([]);
            assert!(!ep_ok(&value), "wrong endpoint type {key}");
        }
        let mut value = endpoints();
        value["endpoints"][0]["extra"] = json!(0);
        assert!(!ep_ok(&value));
        let raw = String::from_utf8(bytes(&endpoints())).unwrap().replacen(
            "\"port\":41001",
            "\"port\":41001,\"port\":41001",
            1,
        );
        assert!(EndpointsV1::parse(raw.as_bytes()).is_err());
        let raw = String::from_utf8(bytes(&command()))
            .unwrap()
            .replace("\"env\":{}", "\"env\":{\"LANG\":\"C\",\"LANG\":\"C\"}");
        assert!(CommandV1::parse(raw.as_bytes()).is_err());
    }

    #[test]
    fn command_string_argv_environment_and_total_quotas() {
        let mut value = command();
        for valid in [
            "/x".to_string(),
            format!("/{}", "a".repeat(STRING_MAX_BYTES - 1)),
        ] {
            value["executable"] = json!(valid);
            assert!(cmd_ok(&value));
        }
        for invalid in [
            "".to_string(),
            "/".into(),
            "relative".into(),
            "/a/".into(),
            "/a//b".into(),
            "/a/./b".into(),
            "/a/../b".into(),
            "/a\0".into(),
            format!("/{}", "a".repeat(STRING_MAX_BYTES)),
        ] {
            value["executable"] = json!(invalid);
            assert!(!cmd_ok(&value));
        }
        let mut value = command();
        value["argv"] = json!([]);
        assert!(cmd_ok(&value));
        value["argv"] = json!(vec![""; ARGV_MAX_ENTRIES]);
        assert!(cmd_ok(&value));
        value["argv"] = json!(vec![""; ARGV_MAX_ENTRIES + 1]);
        assert!(!cmd_ok(&value));
        for field in ["argv", "env"] {
            for (text, good) in [
                ("a".repeat(STRING_MAX_BYTES), true),
                ("é".repeat(STRING_MAX_BYTES / 2), true),
                ("é".repeat(STRING_MAX_BYTES / 2 + 1), false),
                ("a".repeat(STRING_MAX_BYTES + 1), false),
                ("\0".into(), false),
            ] {
                let mut value = command();
                value[field] = if field == "argv" {
                    json!([text])
                } else {
                    json!({"LANG": text})
                };
                assert_eq!(cmd_ok(&value), good, "{field}");
            }
        }
        let mut value = command();
        value["env"] = json!({"LANG":"C", "LC_ALL":"C", "TZ":"UTC"});
        assert!(cmd_ok(&value));
        for key in ["HOME", "LD_PRELOAD", "PATH", "lang", "LANG\0"] {
            value["env"] = json!({key: "x"});
            assert!(!cmd_ok(&value));
        }
        value["env"] = Value::Object(
            (0..=ENV_MAX_ENTRIES)
                .map(|i| (format!("key{i}"), json!("")))
                .collect(),
        );
        assert!(!cmd_ok(&value));
        let mut typed = CommandV1::parse(&bytes(&command())).unwrap();
        typed.env = (0..=ENV_MAX_ENTRIES)
            .map(|i| (format!("key{i}"), String::new()))
            .collect();
        assert!(matches!(
            typed.validate(),
            Err(ContractError::Invalid("env count"))
        ));
        let mut typed = CommandV1::parse(&bytes(&command())).unwrap();
        typed.argv = vec!["a".repeat(STRING_MAX_BYTES); ARGV_MAX_ENTRIES];
        assert!(matches!(
            typed.validate(),
            Err(ContractError::Invalid("command encoded bytes"))
        ));
        for bad in ["bounded-v2", "bounded-v1\0", ""] {
            let mut value = command();
            value["resource_profile"] = json!(bad);
            assert!(!cmd_ok(&value));
        }
    }

    #[test]
    fn identity_grammar_and_relying_party_exclusions() {
        for fixture in [command(), configured()] {
            let parse = if fixture.get("argv").is_some() {
                cmd_ok
            } else {
                marker_ok
            };
            for uid in [
                json!(0),
                json!(u32::MAX),
                json!(u64::from(u32::MAX) + 1),
                json!(-1),
                json!(1.0),
                json!("1"),
            ] {
                let mut value = fixture.clone();
                value["agent_uid"] = uid;
                assert!(!parse(&value));
            }
            for uid in [1, u32::MAX - 1] {
                let mut value = fixture.clone();
                value["agent_uid"] = json!(uid);
                assert!(parse(&value));
            }
            for (id, good) in [
                ("a".repeat(7), false),
                ("a".repeat(8), true),
                ("f".repeat(64), true),
                ("a".repeat(65), false),
                ("ABCDEF12".into(), false),
                ("abcdefg1".into(), false),
                ("abcdef1\0".into(), false),
            ] {
                let mut value = fixture.clone();
                value["fortress_id"] = json!(id);
                assert_eq!(parse(&value), good);
            }
        }
        let identity = IdentityConstraints {
            agent_uid: TEST_UID,
            fortress_id: TEST_FORTRESS,
            service_uid: TEST_UID + 1,
            operator_uid: 1000,
            overflow_uid: 65534,
            system_uid_allow_ceiling: 1000,
        };
        let cmd = CommandV1::parse(&bytes(&command())).unwrap();
        let marker = ConfiguredV1::parse(&bytes(&configured())).unwrap();
        assert!(cmd.validate_identity(&identity).is_ok());
        assert!(marker.validate_identity(&identity).is_ok());
        for changed in [
            IdentityConstraints {
                agent_uid: TEST_UID + 1,
                ..identity.clone()
            },
            IdentityConstraints {
                fortress_id: "abcdef12",
                ..identity.clone()
            },
            IdentityConstraints {
                service_uid: TEST_UID,
                ..identity.clone()
            },
            IdentityConstraints {
                operator_uid: TEST_UID,
                ..identity.clone()
            },
            IdentityConstraints {
                overflow_uid: TEST_UID,
                ..identity.clone()
            },
            IdentityConstraints {
                system_uid_allow_ceiling: TEST_UID,
                ..identity.clone()
            },
        ] {
            assert!(cmd.validate_identity(&changed).is_err());
            assert!(marker.validate_identity(&changed).is_err());
        }
    }

    #[test]
    fn endpoint_schedule_integer_and_shape_bounds() {
        for (field, fixed) in [
            ("initial_delay_ms", INITIAL_DELAY_MS),
            ("attempt_timeout_ms", ATTEMPT_TIMEOUT_MS),
            ("max_response_bytes", MAX_RESPONSE_BYTES),
        ] {
            for bad in [
                json!(fixed - 1),
                json!(fixed + 1),
                json!(-1),
                json!(f64::from(fixed)),
                json!(fixed.to_string()),
                json!(u64::from(u32::MAX) + 1),
            ] {
                let mut value = endpoints();
                value[field] = bad;
                assert!(!ep_ok(&value), "{field}");
            }
        }
        for count in [ENDPOINT_COUNT - 1, ENDPOINT_COUNT + 1] {
            let mut value = endpoints();
            let entry = value["endpoints"][0].clone();
            value["endpoints"]
                .as_array_mut()
                .unwrap()
                .resize(count, entry);
            assert!(!ep_ok(&value));
        }
        let mut value = endpoints();
        value["endpoints"].as_array_mut().unwrap().swap(0, 1);
        assert!(!ep_ok(&value));
        for field in ["family", "role", "protocol"] {
            for bad in ["other", "", "\0"] {
                let mut value = endpoints();
                value["endpoints"][0][field] = json!(bad);
                assert!(!ep_ok(&value));
            }
        }
        for bad in [json!(0), json!(-1), json!(65536), json!(1.0), json!("1")] {
            let mut value = endpoints();
            value["endpoints"][0]["port"] = bad;
            assert!(!ep_ok(&value));
        }
        for port in [1, u16::MAX] {
            let mut value = endpoints();
            value["endpoints"][0]["port"] = json!(port);
            assert!(ep_ok(&value));
        }
        for bad in [
            json!(0),
            json!(2),
            json!(4),
            json!(-1),
            json!(256),
            json!(3.0),
            json!("3"),
        ] {
            let mut value = endpoints();
            value["endpoints"][0]["attempts"] = bad;
            assert!(!ep_ok(&value));
        }
        let mut value = endpoints();
        for ep in value["endpoints"].as_array_mut().unwrap() {
            ep["attempts"] = json!(0);
        }
        assert!(EndpointsV1::parse_for(&bytes(&value), EndpointPurpose::FaultInstrument).is_err());
        value["endpoints"][0]["attempts"] = json!(1);
        assert!(EndpointsV1::parse_for(&bytes(&value), EndpointPurpose::FaultInstrument).is_ok());
        assert!(!ep_ok(&value));
        value["endpoints"][0]["attempts"] = json!(ATTEMPTS_PER_ENDPOINT + 1);
        assert!(EndpointsV1::parse_for(&bytes(&value), EndpointPurpose::FaultInstrument).is_err());
    }

    #[test]
    fn endpoint_literals_tuples_and_public_keys() {
        for bad in [
            "".to_string(),
            "a".repeat(IP_MAX_BYTES + 1),
            "é".into(),
            "example.com".into(),
            "192.0.2.10/32".into(),
            "fe80::1%eth0".into(),
            "::1".into(),
            "192.0.2.10\0".into(),
        ] {
            let mut value = endpoints();
            value["endpoints"][0]["ip"] = json!(bad);
            assert!(!ep_ok(&value));
        }
        let mut value = endpoints();
        value["endpoints"][3]["ip"] = json!("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255");
        assert_eq!(
            value["endpoints"][3]["ip"].as_str().unwrap().len(),
            IP_MAX_BYTES
        );
        assert!(ep_ok(&value));
        let mut value = endpoints();
        value["endpoints"][2]["ip"] = value["endpoints"][0]["ip"].clone();
        assert!(!ep_ok(&value));
        let mut value = endpoints();
        value["endpoints"][5]["ip"] = json!("2001:0db8:0:0:0:0:0:0010");
        assert!(!ep_ok(&value));
        let mut value = endpoints();
        value["endpoints"][0]["response_public_key_hex"] = json!(TEST_KEY);
        assert!(!ep_ok(&value));
        for bad in [
            Value::Null,
            json!("a".repeat(PUBLIC_KEY_HEX_BYTES - 1)),
            json!("a".repeat(PUBLIC_KEY_HEX_BYTES + 1)),
            json!(TEST_KEY.to_uppercase()),
            json!("g".repeat(PUBLIC_KEY_HEX_BYTES)),
            json!("0".repeat(PUBLIC_KEY_HEX_BYTES)),
            json!("\0".repeat(PUBLIC_KEY_HEX_BYTES)),
        ] {
            let mut value = endpoints();
            value["endpoints"][2]["response_public_key_hex"] = bad;
            assert!(!ep_ok(&value));
        }
    }

    #[test]
    fn configured_digests_signature_and_generation_bounds() {
        for field in [
            "command_sha256",
            "endpoints_sha256",
            "public_pin_sha256",
            "policy_sha256",
        ] {
            for bad in [
                "a".repeat(SHA256_HEX_BYTES - 1),
                "a".repeat(SHA256_HEX_BYTES + 1),
                "A".repeat(SHA256_HEX_BYTES),
                "g".repeat(SHA256_HEX_BYTES),
                "\0".repeat(SHA256_HEX_BYTES),
            ] {
                let mut value = configured();
                value[field] = json!(bad);
                assert!(!marker_ok(&value));
            }
        }
        for bad in [
            "a".repeat(SIGNATURE_B64URL_BYTES - 1),
            "a".repeat(SIGNATURE_B64URL_BYTES + 1),
            "!".repeat(SIGNATURE_B64URL_BYTES),
            "A".repeat(SIGNATURE_B64URL_BYTES - 1) + "B",
        ] {
            let mut value = configured();
            value["policy_signature_b64url"] = json!(bad);
            assert!(!marker_ok(&value));
        }
        for length in [
            ed25519_dalek::SIGNATURE_LENGTH - 1,
            ed25519_dalek::SIGNATURE_LENGTH + 1,
        ] {
            let mut value = configured();
            value["policy_signature_b64url"] = json!(URL_SAFE_NO_PAD.encode(vec![0; length]));
            assert!(matches!(
                ConfiguredV1::parse(&bytes(&value)),
                Err(ContractError::Invalid("policy signature bytes"))
            ));
        }
        for good in [0, u64::MAX] {
            let mut value = configured();
            value["policy_generation"] = json!(good);
            assert!(marker_ok(&value));
        }
        for bad in [json!(-1), json!(1.0), json!("1")] {
            let mut value = configured();
            value["policy_generation"] = bad;
            assert!(!marker_ok(&value));
        }
        let raw = String::from_utf8(bytes(&configured())).unwrap().replace(
            "\"policy_generation\":1",
            "\"policy_generation\":18446744073709551616",
        );
        assert!(ConfiguredV1::parse(raw.as_bytes()).is_err());
    }

    #[test]
    fn object_shape_and_early_quota_rejections() {
        let positional_command = json!([
            VERSION,
            TEST_UID,
            TEST_FORTRESS,
            STANDIN_PATH,
            ["--endpoints", ENDPOINTS_PATH],
            {},
            RESOURCE_PROFILE
        ]);
        assert!(CommandV1::parse(&bytes(&positional_command)).is_err());
        let ep = endpoints();
        let positional_endpoints = json!([
            VERSION,
            INITIAL_DELAY_MS,
            ATTEMPT_TIMEOUT_MS,
            MAX_RESPONSE_BYTES,
            ep["endpoints"]
        ]);
        assert!(EndpointsV1::parse(&bytes(&positional_endpoints)).is_err());
        let mut ep = endpoints();
        ep["endpoints"][0] = json!(["ipv4", "deny", "tcp", "192.0.2.10", 41001, 3, null]);
        assert!(!ep_ok(&ep));
        let marker = ConfiguredV1::parse(&bytes(&configured())).unwrap();
        let positional_marker = json!([
            marker.version,
            marker.agent_uid,
            marker.fortress_id,
            marker.command_sha256,
            marker.endpoints_sha256,
            marker.public_pin_sha256,
            marker.policy_generation,
            marker.policy_signature_b64url,
            marker.policy_sha256
        ]);
        assert!(ConfiguredV1::parse(&bytes(&positional_marker)).is_err());
        let mut ep = endpoints();
        ep["endpoints"][0]["ip"] = json!("a".repeat(IP_MAX_BYTES + 1));
        assert!(matches!(
            EndpointsV1::parse(&bytes(&ep)),
            Err(ContractError::Invalid("ip bytes"))
        ));
        let mut value = command();
        value["env"] = Value::Object(
            (0..=ENV_MAX_ENTRIES)
                .map(|i| (format!("key{i}"), json!("")))
                .collect(),
        );
        assert!(matches!(
            CommandV1::parse(&bytes(&value)),
            Err(ContractError::Json(_))
        ));
        for bad in [json!(null), json!(true), json!(1), json!([]), json!({})] {
            let mut value = command();
            value["env"] = json!({"LANG": bad});
            assert!(!cmd_ok(&value));
        }
    }

    #[test]
    fn policy_paths_and_fixed_resource_budget() {
        let paths = PolicyPaths::for_fortress(TEST_FORTRESS).unwrap();
        assert_eq!(
            paths.directory,
            PathBuf::from(format!("/var/lib/sanctuary/{TEST_FORTRESS}/policy/egress"))
        );
        assert_eq!(paths.pin, paths.directory.join("pinned.key"));
        assert_eq!(paths.manifest, paths.directory.join("manifest.json"));
        assert_eq!(paths.rules, paths.directory.join("rules"));
        assert!(PolicyPaths::for_fortress("../escape").is_err());
        assert_eq!(PLANNED_WAL_MAX_BYTES, 71_303_168); // Frozen proof ledger arithmetic.
        assert_eq!(WORKSPACE_MAX_BYTES, 64 * MIB);
        assert_eq!(MEMORY_MAX_BYTES, 512 * MIB);
        assert_eq!(OBSERVATION_MAX_BYTES, 64 * KIB);
        assert_eq!(WORKSPACE_MAX_INODES, 4096);
        assert_eq!(TASKS_MAX, 64);
        assert_eq!(CORE_MAX_BYTES, 0);
    }
}
