//! The agent template unit's start-time checks (slice B).
//!
//! `systemd/sanctuary-agent@.service` starts one agent per uid; its instance
//! name is the uid. Before `ExecStart=` it runs two read-only verbs of this
//! daemon binary, in this order:
//!
//! 1. `--agent-credential-check <uid>`, as the instance uid: the process's own
//!    kernel credentials must be exactly the instance's.
//! 2. `--agent-start-gate <uid> --fortress-id <id> --trusted-service-uid <uid>`,
//!    as root: the live owned table must bind exactly that uid, and the uid
//!    must not be the wall's trusted control uid.
//!
//! Register id: `defect.linux-no-agent-launcher-assigns-or-drops-to-the-agent-uid`.

#[cfg(all(test, target_os = "linux"))]
mod tb4_unit_bounds {
    //! TB4: the agent unit's bounds against the one `nft` call the gate makes.

    /// The shipped agent unit. Must match `systemd/sanctuary-agent@.service`.
    const AGENT_UNIT: &str = include_str!("../systemd/sanctuary-agent@.service");
    /// The shipped wall unit. Must match `systemd/sanctuary-castle-wall.service`.
    const WALL_UNIT: &str = include_str!("../systemd/sanctuary-castle-wall.service");

    /// The single non-comment value of `key` in a unit (the agent unit's
    /// canonical form is enforced by `tests/agent_unit.rs`).
    fn value<'a>(unit: &'a str, key: &str) -> &'a str {
        let values: Vec<&str> = unit
            .lines()
            .filter(|line| !line.starts_with('#'))
            .filter_map(|line| line.strip_prefix(key)?.strip_prefix('='))
            .collect();
        assert_eq!(values.len(), 1, "exactly one {key}= expected");
        values[0]
    }

    #[test]
    fn tb4_the_start_timeout_exceeds_one_nft_call_and_the_stop_timeout_matches_the_wall() {
        let start: u64 = value(AGENT_UNIT, "TimeoutStartSec")
            .parse()
            .expect("TimeoutStartSec is whole seconds");
        // The gate makes exactly one bounded nft call; a start timeout at or
        // below its worst case would kill a healthy gate mid-read.
        assert!(
            std::time::Duration::from_secs(start) > crate::nftables::NFT_CALL_WORST_CASE,
            "agent TimeoutStartSec {start}s must exceed NFT_CALL_WORST_CASE {:?}",
            crate::nftables::NFT_CALL_WORST_CASE
        );
        assert_eq!(
            value(AGENT_UNIT, "TimeoutStopSec"),
            value(WALL_UNIT, "TimeoutStopSec"),
            "the agent's TimeoutStopSec must equal the wall's"
        );
        assert_eq!(
            value(AGENT_UNIT, "ExecStart"),
            crate::protected_agent::profile::EXECUTABLE_PATH,
            "ExecStart= must match profile::EXECUTABLE_PATH"
        );
    }
}
