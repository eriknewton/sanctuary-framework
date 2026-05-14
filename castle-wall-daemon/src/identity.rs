//! Agent identity encoders for kernel-facing resource names.
//!
//! Castle Wall must keep raw agent IDs distinct when deriving systemd unit
//! names and nftables chain names. The encoder preserves already-safe legacy
//! IDs, escapes unsafe bytes reversibly for normal lengths, and falls back to
//! a SHA-256 suffix only when a platform name budget would be exceeded.

use sha2::{Digest, Sha256};

const HASH_PREFIX: &str = "-h";
const HASH_HEX_LEN: usize = 64;

pub(crate) fn encode_agent_component(agent_id: &str, max_len: usize) -> String {
    let encoded = encode_agent_id_bytes(agent_id);
    if encoded.len() <= max_len {
        return encoded;
    }

    let hash = sha256_hex(agent_id.as_bytes());
    let suffix_len = HASH_PREFIX.len() + HASH_HEX_LEN;
    if max_len <= suffix_len {
        return hash[..max_len].to_string();
    }

    let prefix_budget = max_len - suffix_len;
    let mut prefix = String::with_capacity(prefix_budget + suffix_len);
    for ch in encoded.chars() {
        let next_len = prefix.len() + ch.len_utf8();
        if next_len > prefix_budget {
            break;
        }
        prefix.push(ch);
    }
    prefix.push_str(HASH_PREFIX);
    prefix.push_str(&hash);
    prefix
}

fn encode_agent_id_bytes(agent_id: &str) -> String {
    if agent_id.is_empty() {
        return "_x00_".to_string();
    }

    let mut encoded = String::with_capacity(agent_id.len());
    for byte in agent_id.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.' => {
                encoded.push(byte as char);
            }
            _ => {
                use std::fmt::Write;
                let _ = write!(encoded, "_x{byte:02x}_");
            }
        }
    }
    encoded
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut s = String::with_capacity(out.len() * 2);
    for b in out {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_legacy_ids_are_preserved() {
        assert_eq!(
            encode_agent_component("agent_1-prod.v2", 64),
            "agent_1-prod.v2"
        );
    }

    #[test]
    fn unsafe_bytes_are_escaped_distinctly() {
        assert_eq!(encode_agent_component("agent/a", 64), "agent_x2f_a");
        assert_eq!(encode_agent_component("agent_a", 64), "agent_a");
        assert_ne!(
            encode_agent_component("agent/a", 64),
            encode_agent_component("agent_a", 64)
        );
    }

    #[test]
    fn oversized_components_keep_hash_suffix_within_budget() {
        let raw = format!("agent/{}", "x".repeat(300));
        let encoded = encode_agent_component(&raw, 80);
        assert_eq!(encoded.len(), 80);
        assert!(encoded.contains("-h"));
    }
}
