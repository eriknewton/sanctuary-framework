//! nftables CLI shell-out wrappers.
//!
//! Per scope-lock section 1 Option A: the daemon shells out to the `nft` binary
//! with atomic ruleset replacement, installs rules in a dedicated
//! `sanctuary-castle` table (E7.2 namespace separation), and binds an agent's
//! rules to that agent's uid via `meta skuid <uid>` matches.
//!
//! ## What `meta skuid` matches, precisely
//!
//! On Linux 6.8 `nft_meta` reads `sock->file->f_cred->fsuid`, translated through
//! the user namespace of the socket's network namespace. The expression is
//! UNAVAILABLE, so the packet does not match, in exactly three cases: no socket,
//! no backing file, or a socket-versus-packet network-namespace mismatch. A uid
//! with NO mapping in that user namespace is NOT one of them: the kernel renders
//! it through `from_kuid_munged` as the overflow uid (65534), which then matches
//! nothing the manifest names. Either way the packet falls through to the base
//! chain's `policy accept`, but the two are different mechanisms and must not be
//! collapsed. The guarantee is bounded to SOCKET credentials, and only while the
//! rule exists: an inherited or passed socket, another network namespace, a
//! `setfsuid` divergence, or a uid hop on a NEW socket all leave the match. Each
//! of those is a row in the private defect register; none is closed here.
//!
//! All kernel-touching functions are `#[cfg(target_os = "linux")]`-gated;
//! on macOS (the dev sandbox) the stubs return structured errors so
//! `cargo check` passes cross-platform.

#[cfg(target_os = "linux")]
use std::sync::Mutex;
use std::sync::OnceLock;

// The net's uid values come through the shared validator ONLY. `ConfinedUidSet`
// has a private field there, so this module can carry it and render it but can
// never mint one from a raw `u32`.
// Must match `crate::safety_net_uid::ConfinedUidSet`'s constructor contract.
use crate::safety_net_uid::{validate_safety_net_uid, ConfinedUidSet, HostOverflowUid};

/// Errors emitted by the nftables module.
#[derive(Debug, thiserror::Error)]
pub enum NftablesError {
    #[error("nftables not available on this platform")]
    NotAvailableOnPlatform,
    #[error("nft binary missing: {0}")]
    BinaryMissing(String),
    #[error("nft invocation failed: {0}")]
    InvocationFailed(String),
    #[error("failed to parse nft output: {0}")]
    ParseFailed(String),
    /// A table named `sanctuary-castle` exists but does not have the shape this
    /// daemon installs (missing/foreign base output chain, wrong hook, or a
    /// non-`accept` policy). The daemon refuses to adopt or clobber foreign
    /// state that merely shares its table name; it neither enforces through an
    /// unknown ruleset nor deletes another owner's table.
    #[error("foreign or incompatible sanctuary-castle table: {0}")]
    ForeignState(String),
}

/// Identifier for a wrapped agent's uid-bound ruleset.
///
/// `fortress_id` is not decoration: it is a seal input, so the same agent id and
/// uid under a DIFFERENT fortress produce a different `agent_uid_seal` and the
/// live rule fails to verify. Must match `AllowlistManifest.fortress_id` in
/// `src/manifest/verify.rs` and `PolicySnapshot::fortress_id` in `src/policy.rs`;
/// the verification side reads it from the CURRENT policy snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRulesetId {
    pub agent_id: String,
    pub fortress_id: String,
}

/// The manifest-derived kernel binding one agent's rules are emitted from.
///
/// BOTH fields come from the SIGNED manifest's `agent_origin` (must match
/// `AgentOrigin.agent_uid` / `AgentOrigin.system_uid_allow_ceiling` in
/// `src/manifest/verify.rs`, admitted by `confined_agent_uid_from_loaded_manifest`
/// in `src/policy.rs`); neither is ever read from local configuration. The
/// ceiling travels WITH the uid so the emission site can prove, at the moment it
/// seals a uid into a kernel rule, that the uid still clears the floor admission
/// accepted it under — a snapshot swap between admission and emission cannot
/// silently lower it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentUidBinding {
    pub agent_uid: u32,
    pub system_uid_allow_ceiling: u32,
}

/// What a verification site knows about the agent binding the live kernel rules
/// are ALLOWED to carry. Named states, because the three are not interchangeable
/// and the difference is the whole security content of the check: an
/// internally-consistent inventory whose uid and seal were BOTH rewritten is
/// refused only by [`Self::Confined`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedAgentBinding {
    /// The identity this process FROZE at boot confines `agent_uid` under
    /// `fortress_id`. Every live per-agent binding must carry exactly this uid
    /// AND a seal that recomputes under this fortress id. This is the trusted
    /// expectation the design names, and it is read from the write-once armed
    /// identity cell (`AdmittedIdentity` in `src/decision.rs`, by way of
    /// `current_expected_agent_binding` in `src/runtime_providers.rs`), never
    /// re-derived from the live store: a reload that would change the uid is
    /// REFUSED while armed, so there is no later value for a comparison to drift
    /// against.
    Confined { fortress_id: String, agent_uid: u32 },
    /// The identity this process FROZE at boot confines NO agent uid (the frozen
    /// cell is `Unconfined`: absent `agent_origin`, or a non-`uid` mode), or the
    /// cell is not set yet because the boot freeze has not run (the freeze runs
    /// BEFORE table creation, so an unset cell here is never explained by the
    /// table having just been created). Read from the same
    /// write-once cell as [`Self::Confined`] (`AdmittedIdentity` in
    /// `src/decision.rs`, by way of `current_expected_agent_binding` in
    /// `src/runtime_providers.rs`), never from a fresh store read, so the two
    /// variants cannot disagree about which snapshot they describe. Any live
    /// per-agent binding is unverifiable against a trusted expectation under this
    /// variant, so it reads foreign: absent evidence is not passing evidence.
    NoneConfined,
    /// Shape, seal, agreement and cardinality only, under `fortress_id`, with the
    /// uid NOT compared against a manifest expectation.
    ///
    /// Used ONLY where the caller genuinely holds no trusted expectation and the
    /// operation's direction is already fail-closed: the pre-mutation ownership
    /// precondition (which is followed by a real health poll that DOES compare),
    /// and the disarm path (which deletes the table outright, so refusing on a
    /// uid mismatch would wedge recovery rather than protect anything). It is
    /// never correct on the reclaim, adoption or health paths.
    SealOnly { fortress_id: String },
    /// Shape, body/jump agreement and cardinality only, with NEITHER the seal
    /// recomputed nor the uid compared, because the caller holds neither a
    /// fortress id nor a manifest expectation.
    ///
    /// Used ONLY by the disarm path, whose verification exists to answer one
    /// question — has this table drifted off the identity we captured, so that
    /// deleting it would clobber someone else's state? — and which then DELETES
    /// the table. Refusing there on a seal or uid mismatch would wedge the one
    /// recovery path an operator has, while protecting nothing: the table is
    /// about to cease to exist either way. It is never correct on a path that
    /// keeps the table standing.
    StructureOnly,
}

impl ExpectedAgentBinding {
    /// The fortress id the seal is recomputed under, when the site has one.
    /// [`Self::NoneConfined`] has none and needs none: it refuses every
    /// per-agent binding before any seal is recomputed.
    fn seal_fortress_id(&self) -> Option<&str> {
        match self {
            Self::Confined { fortress_id, .. } | Self::SealOnly { fortress_id } => {
                Some(fortress_id.as_str())
            }
            Self::NoneConfined | Self::StructureOnly => None,
        }
    }

    /// Whether a live per-agent binding may stand without a recomputable seal.
    /// True only for [`Self::StructureOnly`]; every other state either supplies
    /// a fortress id to recompute against or refuses the binding outright.
    fn tolerates_unverifiable_seal(&self) -> bool {
        matches!(self, Self::StructureOnly)
    }
}

/// The dedicated nftables table name PRODUCTION installs into. Per scope-lock
/// section 7 E7.2, the daemon installs into its own table so it never conflicts
/// with ufw / firewalld / operator rules.
///
/// Every operational site reads [`castle_table()`], not this constant, so a test
/// binary can be pointed at an isolated table name; the resolver's DEFAULT is
/// this value, so production is byte-for-byte unchanged.
pub const CASTLE_TABLE: &str = "sanctuary-castle";

/// Prefix every isolated test table name must carry. Enforced by
/// [`use_isolated_castle_table`], so the isolation seam can never be used to
/// point a daemon at an arbitrary operator table.
#[cfg(any(test, feature = "test-isolation"))]
pub const ISOLATED_TABLE_PREFIX: &str = "sanctuary-castle-test-";

/// Process-wide resolved table name. Set at most once, before any nftables call.
static ACTIVE_CASTLE_TABLE: OnceLock<String> = OnceLock::new();

/// The nftables table this process operates on.
///
/// Resolves to [`CASTLE_TABLE`] unless an isolated name was installed first.
/// The table is a HOST-GLOBAL kernel object, so this is process-wide rather than
/// threaded through ~100 call sites: a second table name inside one process
/// would be a split-brain, not a feature.
///
/// The reason it is overridable at all: `cargo test` on a Linux host drove the
/// real `sanctuary-castle` table, and its cleanup ran
/// `nft delete table inet sanctuary-castle` — deleting the operator's LIVE
/// enforcement table (AGENTS.md, "the operator's machine is not a fixture").
/// The override exists only in `cfg(test)` and `feature = "test-isolation"`
/// builds; the shipped binary contains no way to call it.
pub fn castle_table() -> &'static str {
    ACTIVE_CASTLE_TABLE
        .get_or_init(|| CASTLE_TABLE.to_string())
        .as_str()
}

/// Has this process resolved the PRODUCTION table name?
///
/// The isolation proof the test suite asserts: after installing an isolated
/// table, this must stay false for the whole run. A `false` here means no code
/// path in this process has named the operator's live table.
pub fn production_castle_table_in_use() -> bool {
    ACTIVE_CASTLE_TABLE
        .get()
        .map(|name| name == CASTLE_TABLE)
        .unwrap_or(false)
}

/// Point this process at an isolated table for the rest of its life.
///
/// Fails (rather than silently no-opping) when the table name has ALREADY been
/// resolved, because a caller that has begun touching one table cannot be moved
/// to another without leaking the first. Refuses any name that is not
/// [`ISOLATED_TABLE_PREFIX`]-prefixed, so this can never redirect a daemon onto
/// an operator's table.
///
/// Absent from the shipped binary: `cfg(test)` covers the crate's own unit tests,
/// and `feature = "test-isolation"` covers the integration test binaries (which
/// declare it through `required-features`). A release build has neither.
#[cfg(any(test, feature = "test-isolation"))]
pub fn use_isolated_castle_table(name: &str) -> Result<&'static str, String> {
    if !name.starts_with(ISOLATED_TABLE_PREFIX) {
        return Err(format!(
            "an isolated castle table must be named `{ISOLATED_TABLE_PREFIX}<tag>`; \
             refusing `{name}` so this seam can never redirect a daemon onto a \
             production or operator-owned table"
        ));
    }
    match ACTIVE_CASTLE_TABLE.set(name.to_string()) {
        Ok(()) => Ok(castle_table()),
        Err(_) => {
            let active = castle_table();
            if active == name {
                Ok(active)
            } else {
                Err(format!(
                    "this process already resolved the castle table as `{active}`; refusing \
                     to switch to `{name}` (state acquired under the first name would leak)"
                ))
            }
        }
    }
}

/// The nftables table family. `inet` covers both IPv4 and IPv6.
pub const CASTLE_FAMILY: &str = "inet";
const NFT_CHAIN_MAX_LEN: usize = 256;
const AGENT_CHAIN_PREFIX: &str = "agent_";

/// Prefix of the ownership marker stamped as a `comment` on the acquisition
/// path's table. The full marker is `OWNER_MARKER_PREFIX` followed by a random
/// per-acquisition nonce, so two acquisitions (even of a same-named table) are
/// distinguishable and a foreign table that merely shares the `sanctuary-castle`
/// name cannot forge it. The marker is a table COMMENT, not a rule, so it does
/// not count against the "zero rules" ownership invariant. Must match the marker
/// the journal records for the same acquisition (see `ownership_journal`).
pub const OWNER_MARKER_PREFIX: &str = "sanctuary-castle-owner:v1:";

/// Rule `comment` on the safety net's DROP rule, which names the confined
/// identity. This and the two comments below are the net's v2 wire shape: they
/// are what `is_deny_all_safety_net_json` reads back to prove a live table is
/// this daemon's own net, and the disarm verb's recovery arm keys on that same
/// recognition. Emitter and recogniser are both in this file; the values are a
/// PERMANENT product shape and must match the three rules in `D1` of
/// `Review/Sanctuary/Linux_Safety_Net_Carveout_Design_2026-09-17.md`. They carry
/// no `OWNER_MARKER_PREFIX`: the net is deliberately NOT a captured owned table
/// (it is `policy drop`, while the owned parser requires `policy accept`).
pub const NET_RULE_COMMENT_IDENTITY: &str = "sanctuary-castle-net:v2:confined-identity";

/// Rule `comment` on the kernel neighbour-discovery accept rule.
/// Must match the rule-2 comment in `is_deny_all_safety_net_json`.
pub const NET_RULE_COMMENT_KERNEL_ND: &str = "sanctuary-castle-net:v2:kernel-nd";

/// Rule `comment` on the "every other principal" accept rule.
/// Must match the rule-3 comment in `is_deny_all_safety_net_json`.
pub const NET_RULE_COMMENT_OTHERS: &str = "sanctuary-castle-net:v2:other-principals";

/// The ONLY ICMPv6 types the net accepts while armed: the kernel's own
/// neighbour-discovery messages, which carry no socket (`skb->sk` is null) and
/// would otherwise fall to the drop policy and take IPv6 connectivity, an IPv6
/// ssh session included, down with the agent.
///
/// MLD is deliberately ABSENT. An ordinary IPv6 datagram socket can join and
/// leave multicast groups with no capability, and each membership change makes
/// the kernel emit an MLD report with no socket, so an MLD accept would be a
/// link-local channel the confined agent can drive. The cost is recorded as a
/// residual in the design memo (IPv6 multicast memberships age out on
/// MLD-snooping links while the net is armed; the IPv4 operator path is the
/// documented repair path).
///
/// Must match the rule-2 type set the recogniser requires in
/// `is_deny_all_safety_net_json`.
pub const KERNEL_ND_ICMPV6_TYPES: [&str; 3] = [
    "nd-neighbor-solicit",
    "nd-neighbor-advert",
    "nd-router-solicit",
];

/// Largest confined-uid set the net will name in one rule.
///
/// DERIVATION, not a preference: one agent uid and one gate uid per signed
/// manifest, so 256 entries is 128 distinct admitted identities within a single
/// boot with no disarm. An operating host rotates its confined identity a handful
/// of times at most; a set larger than this comes from an attacker-crafted
/// inventory, not from operation. Over the bound the net falls back to the
/// host-wide shape with the `deny-set-over-capacity` reason rather than
/// truncating, because a truncated set silently unconfines whichever identity
/// fell off the end.
pub const DENY_SET_MAX: usize = 256;

/// Which principals the deny-all safety net denies.
///
/// `Identity` is the v2 shape and the only shape that preserves operator access:
/// it denies exactly the uids in its [`ConfinedUidSet`] and accepts every other
/// attestable principal. `HostWide` is the v1 shape (a bare `policy drop` base
/// chain, no rules), installed ONLY when no confined identity can be named:
/// an empty deny set, unknown history for this boot, or a deny set over
/// [`DENY_SET_MAX`]. On that shape operator access is NOT preserved, and every
/// refusal and audit row that carries it says so with its reason.
///
/// The variant is CLOSED: `ConfinedUidSet` has a private field and no constructor
/// outside `crate::safety_net_uid`, so no caller anywhere in the crate can place
/// uid 0, this host's `kernel.overflowuid` or `u32::MAX` into rule 1. This is the
/// type-level half of D1c; the ceiling half stays at admission and at the
/// emission floor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyNetScope {
    /// Deny exactly these uids; accept every other attestable principal.
    Identity(ConfinedUidSet),
    /// Deny every uid on this host. Operator access is not preserved.
    HostWide,
}

impl SafetyNetScope {
    /// The uids rule 1 denies, ascending; empty for the host-wide shape (which
    /// denies by policy rather than by naming anyone).
    pub fn denied_uids(&self) -> Vec<u32> {
        match self {
            SafetyNetScope::Identity(set) => set.uids(),
            SafetyNetScope::HostWide => Vec::new(),
        }
    }

    /// The shape tag the audit row and the signed health report carry.
    /// Must match the `shape` values in `D4` of the design memo and in the
    /// `safety_net` state this daemon emits.
    pub fn shape_tag(&self) -> &'static str {
        match self {
            SafetyNetScope::Identity(_) => "v2-confined-identity",
            SafetyNetScope::HostWide => "v1-host-wide",
        }
    }
}

/// Why the net was installed with the scope it was.
///
/// Every host-wide reason is DISTINCT and carries its own refusal sentence,
/// because they are not the same operational situation and an operator acts
/// differently on each. Folding them into one "unrecoverable" message is what made
/// an over-capacity set read as unknown history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyNetReason {
    /// A confined identity was recoverable and the net denies exactly it. This is
    /// the only reason under which operator access is preserved.
    Identity,
    /// No confined identity was recoverable from any of the three sources.
    EmptyDenySet,
    /// The journal's `confined` key is ABSENT on a same-boot record, so neither
    /// the manifest nor the live table can prove this boot's history.
    UnknownHistory,
    /// The deny set is known exactly but is larger than `DENY_SET_MAX`.
    DenySetOverCapacity { count: usize, cap: usize },
}

impl SafetyNetReason {
    /// The tag the audit row and the signed health report carry.
    /// Must match the `reason` values in `D4` of the design memo.
    pub fn tag(&self) -> &'static str {
        match self {
            SafetyNetReason::Identity => "identity",
            SafetyNetReason::EmptyDenySet => "empty-deny-set",
            SafetyNetReason::UnknownHistory => "unknown-history",
            SafetyNetReason::DenySetOverCapacity { .. } => "deny-set-over-capacity",
        }
    }
}

/// The repair order an operator must follow, in the order that WORKS.
///
/// FAILURE MODE this sentence exists to prevent: repairing the wall first and
/// running disarm second does not work while the unit is running, because systemd
/// restarts the daemon into the same refusal and it re-takes the host lock that
/// disarm needs. Stopping the unit first is what makes the other two steps
/// possible.
pub const SAFETY_NET_REPAIR_ORDER: &str =
    "stop the castle-wall unit, repair the wall, then run the disarm verb";

/// The scope sentence a refusal on a net-install path carries, in plain words an
/// operator can act on.
///
/// The identity form names the uids and states explicitly that every other
/// principal is unaffected, because the first question an operator asks on seeing
/// a deny-all net is whether their own session is about to die. Each host-wide
/// form names its OWN reason and then says, in the same sentence, that operator
/// access is NOT preserved on that path.
pub fn safety_net_scope_sentence(scope: &SafetyNetScope, reason: &SafetyNetReason) -> String {
    match scope {
        SafetyNetScope::Identity(set) => format!(
            "the net denies uids {:?}; every other principal, including root and ssh, \
             is unaffected. {SAFETY_NET_REPAIR_ORDER}",
            set.uids()
        ),
        SafetyNetScope::HostWide => {
            let why = match reason {
                SafetyNetReason::EmptyDenySet => "no confined identity was recoverable".to_string(),
                SafetyNetReason::UnknownHistory => "history unknown for this boot".to_string(),
                SafetyNetReason::DenySetOverCapacity { count, cap } => {
                    format!("deny set over capacity ({count} of {cap})")
                }
                // `Identity` cannot pair with the host-wide shape; if it ever
                // does, say so rather than printing a reason that is not true.
                SafetyNetReason::Identity => {
                    "a confined identity was named but the host-wide shape was installed \
                     (this pairing is a defect)"
                        .to_string()
                }
            };
            format!(
                "{why}; the net denies every uid on this host; operator access is not \
                 preserved on this path. {SAFETY_NET_REPAIR_ORDER}"
            )
        }
    }
}

/// The TAGGED `safety_net` state the `kernel_runtime_lost` WAL row and the signed
/// health report carry (design memo D4).
///
/// INVARIANT, and the reason this is a tagged enum rather than a struct with an
/// `installed: bool`: a status request or an audit row emitted WHILE a net install
/// has failed must not attest to a protection that is not in place. A struct with
/// optional fields reads as "installed, details missing"; these variants
/// cannot be confused for one another by a consumer.
///
/// Producer and consumer schemas change together. Must match the `safety_net`
/// object the TypeScript reader parses on the `kernel_runtime_lost` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyNetAuditState {
    /// The net is in the kernel with this exact predicate.
    Installed {
        shape: &'static str,
        reason: &'static str,
        deny_set_size: usize,
        deny_set_max: usize,
        rules: Vec<String>,
        denied_uids: Vec<u32>,
        sources: SafetyNetSources,
        kernel_nd_accepted: Vec<&'static str>,
        unattestable_packets: &'static str,
        coverage: &'static str,
    },
    /// An install was attempted for this scope and FAILED. No protection is
    /// claimed.
    InstallFailed {
        attempted_scope: String,
        error: String,
    },
    /// A prior install succeeded, but this poll did not re-prove kernel presence.
    /// Carries no predicate or coverage assertion.
    Unverified,
    /// No install was attempted on this path (both nft-indeterminate rows).
    NotAttempted,
}

/// Which of the three sources contributed to the deny set, so a reader can tell a
/// set recovered from the journal from one recovered only from the live table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyNetSources {
    pub journal: bool,
    pub manifest: bool,
    pub live_table: bool,
}

/// What the net does with a packet whose sending credential the kernel cannot
/// attest. Named so the audit row and the doc comment cannot drift apart.
pub const SAFETY_NET_UNATTESTABLE_DISPOSITION: &str = "drop-except-kernel-nd";

/// The net's coverage limit, stated on every audit row that claims the net is
/// installed. The net sits on the same hook as the wall, so a packet socket
/// transmits below it; that bound is the launcher's to close, not this net's.
pub const SAFETY_NET_COVERAGE_BOUND: &str = "inet output hook; packet sockets are outside it";

impl SafetyNetAuditState {
    /// Build the `Installed` state for a scope that is now in the kernel.
    #[cfg(any(target_os = "linux", test))]
    pub fn installed(
        scope: &SafetyNetScope,
        reason: &SafetyNetReason,
        sources: SafetyNetSources,
    ) -> Self {
        let denied_uids = scope.denied_uids();
        // The rule texts come from the SAME builder that produced the
        // transaction, so the audit row cannot describe a predicate other than
        // the one installed.
        let rules: Vec<String> = build_deny_all_safety_net_script(scope)
            .lines()
            .filter(|line| line.starts_with("add rule "))
            .map(|line| line.to_string())
            .collect();
        SafetyNetAuditState::Installed {
            shape: scope.shape_tag(),
            reason: reason.tag(),
            deny_set_size: denied_uids.len(),
            deny_set_max: DENY_SET_MAX,
            rules,
            denied_uids,
            sources,
            kernel_nd_accepted: match scope {
                SafetyNetScope::Identity(_) => KERNEL_ND_ICMPV6_TYPES.to_vec(),
                // The host-wide shape carries no rules at all, so it accepts no
                // neighbour discovery either. Saying so is the honest row.
                SafetyNetScope::HostWide => Vec::new(),
            },
            unattestable_packets: SAFETY_NET_UNATTESTABLE_DISPOSITION,
            coverage: SAFETY_NET_COVERAGE_BOUND,
        }
    }

    /// The tag a consumer switches on.
    pub fn tag(&self) -> &'static str {
        match self {
            SafetyNetAuditState::Installed { .. } => "installed",
            SafetyNetAuditState::InstallFailed { .. } => "install_failed",
            SafetyNetAuditState::Unverified => "unverified",
            SafetyNetAuditState::NotAttempted => "not_attempted",
        }
    }

    /// Render as the JSON object the WAL row and the signed report embed.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            SafetyNetAuditState::Installed {
                shape,
                reason,
                deny_set_size,
                deny_set_max,
                rules,
                denied_uids,
                sources,
                kernel_nd_accepted,
                unattestable_packets,
                coverage,
            } => serde_json::json!({
                "state": "installed",
                "shape": shape,
                "reason": reason,
                "deny_set_size": deny_set_size,
                "deny_set_max": deny_set_max,
                "rules": rules,
                "denied_uids": denied_uids,
                "sources": {
                    "journal": sources.journal,
                    "manifest": sources.manifest,
                    "live_table": sources.live_table,
                },
                "kernel_nd_accepted": kernel_nd_accepted,
                "unattestable_packets": unattestable_packets,
                "coverage": coverage,
            }),
            SafetyNetAuditState::InstallFailed {
                attempted_scope,
                error,
            } => serde_json::json!({
                "state": "install_failed",
                "attempted_scope": attempted_scope,
                "error": error,
            }),
            SafetyNetAuditState::Unverified => serde_json::json!({ "state": "unverified" }),
            SafetyNetAuditState::NotAttempted => serde_json::json!({ "state": "not_attempted" }),
        }
    }
}

/// Render an nft set literal (`{ a, b }`) from ascending uids.
///
/// Gated the same way as its only caller, `build_deny_all_safety_net_script`:
/// production-used on Linux and exercised by the cross-platform unit tests, so an
/// ungated definition is a dead-code diagnostic under `clippy -D warnings` on the
/// macOS dev lib build.
#[cfg(any(target_os = "linux", test))]
fn render_uid_set(uids: &[u32]) -> String {
    let members: Vec<String> = uids.iter().map(|u| u.to_string()).collect();
    format!("{{ {} }}", members.join(", "))
}

/// Build the ONE atomic transaction that arms the safety net for `scope`.
///
/// Pure and cross-platform so the exact transaction text, and above all the RULE
/// ORDER, are unit-testable without a kernel.
///
/// INVARIANT, the rule order is the whole carve-out: rule 1 DROPS every
/// attestable packet of the confined identity FIRST, so no later accept is
/// reachable by an agent packet the kernel can attribute (including one sent on
/// an `AF_INET`/`AF_INET6` raw or ping socket). Rule 2 then accepts the kernel's
/// own neighbour-discovery messages, which carry no socket at all and therefore
/// cannot be the agent's. Rule 3 accepts every other attestable principal, which
/// is what keeps root, sshd and an ordinary human user's sockets alive. Reorder
/// these and the net either denies the operator or lets the agent out; a
/// reordered table is refused by the recogniser for exactly that reason.
///
/// Everything the three rules do not match falls to the chain's `policy drop`:
/// an unattestable packet that is not kernel neighbour discovery (a closed
/// socket's queued bytes with no file attached, a TIME_WAIT or orphaned socket,
/// an ICMP error, an outbound packet-too-big) is DROPPED. That is deliberate,
/// and it is why rule 2 exists at all.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn build_deny_all_safety_net_script(scope: &SafetyNetScope) -> String {
    let castle_table = castle_table();
    // add (ensure exists) -> delete (drop any drifted/leftover contents of OUR
    // named table) -> add (fresh empty) -> base output chain, policy DROP. One
    // transaction, so the kernel never observes the intermediate empty state:
    // there is NO fail-open window between the teardown and the drop policy.
    let mut script = format!(
        "add table {CASTLE_FAMILY} {castle_table}\n\
         delete table {CASTLE_FAMILY} {castle_table}\n\
         add table {CASTLE_FAMILY} {castle_table}\n\
         add chain {CASTLE_FAMILY} {castle_table} output \
         {{ type filter hook output priority 0 ; policy drop ; }}\n"
    );
    if let SafetyNetScope::Identity(set) = scope {
        let uid_set = render_uid_set(&set.uids());
        let nd_types = KERNEL_ND_ICMPV6_TYPES.join(", ");
        script.push_str(&format!(
            "add rule {CASTLE_FAMILY} {castle_table} output meta skuid {uid_set} drop \
             comment \"{NET_RULE_COMMENT_IDENTITY}\"\n\
             add rule {CASTLE_FAMILY} {castle_table} output icmpv6 type {{ {nd_types} }} accept \
             comment \"{NET_RULE_COMMENT_KERNEL_ND}\"\n\
             add rule {CASTLE_FAMILY} {castle_table} output meta skuid != {uid_set} accept \
             comment \"{NET_RULE_COMMENT_OTHERS}\"\n"
        ));
    }
    script
}

/// nft's hard cap on a rule `comment`, in bytes (confirmed on nft 1.0.9). A
/// comment over this is rejected at rule-load time, so every marker-bound
/// comment this module emits must be proven to fit BEFORE emission — a
/// load-time rejection mid-transaction leaves the agent with no binding at all.
const NFT_RULE_COMMENT_MAX_LEN: usize = 128;

/// Hex characters in an ownership marker's nonce: the acquisition path reads 16
/// random bytes and hex-encodes them (see `new_owner_marker` in
/// `runtime_providers.rs` and `fresh_install_owner_marker` below), and hex is 2
/// characters per byte.
const OWNER_MARKER_NONCE_HEX_LEN: usize = 2 * 16;

/// Hex characters in an agent-uid seal: [`agent_uid_seal`] truncates SHA-256 to
/// 8 bytes, and hex is 2 characters per byte.
const AGENT_UID_SEAL_HEX_LEN: usize = 2 * 8;

/// The delimiter that separates the agent id from its uid seal inside a
/// marker-bound rule comment. Must match the split the inventory parser performs
/// (`parse_owned_table_inventory`); the parser and the emitter share this
/// constant precisely so the two can never disagree by a typo.
const AGENT_UID_SEAL_INFIX: &str = ":uid:";

/// The LONGEST role infix a SEALED rule comment can carry. `:jump:` is shorter,
/// and `:failclosed:`, though longer still, carries no seal and no agent-uid
/// suffix, so it is not the binding case (its worst comment is
/// marker + 12 + MAX_AGENT_ID_LEN, comfortably inside the cap).
const LONGEST_SEALED_ROLE_INFIX: &str = ":queue:";

/// Longest byte length an agent id may carry and still leave every marker-bound
/// rule comment inside nft's cap. Derived from the parts, never a literal, so a
/// change to the marker, the seal width or the role names moves this with them:
///
/// ```text
///   NFT_RULE_COMMENT_MAX_LEN      128
/// - OWNER_MARKER_PREFIX.len()      26  "sanctuary-castle-owner:v1:"
/// - OWNER_MARKER_NONCE_HEX_LEN     32  16 random bytes as hex
/// - LONGEST_SEALED_ROLE_INFIX.len() 7  ":queue:"
/// - AGENT_UID_SEAL_INFIX.len()      5  ":uid:"
/// - AGENT_UID_SEAL_HEX_LEN         16  8 digest bytes as hex
/// =                                42
/// ```
///
/// This TIGHTENS the previous 128-byte agent-id grammar. An agent id between 43
/// and 128 bytes that was accepted before is now refused at
/// `validate_agent_binding_input` rather than accepted and then rejected by nft
/// with an opaque load-time error.
const MAX_AGENT_ID_LEN: usize = NFT_RULE_COMMENT_MAX_LEN
    - OWNER_MARKER_PREFIX.len()
    - OWNER_MARKER_NONCE_HEX_LEN
    - LONGEST_SEALED_ROLE_INFIX.len()
    - AGENT_UID_SEAL_INFIX.len()
    - AGENT_UID_SEAL_HEX_LEN;

/// The exact, verified identity of a `sanctuary-castle` table THIS daemon
/// created and owns. (blocker 2/3)
///
/// Ownership is not "a table by that name exists"; it is this precise tuple:
/// the nft-assigned table handle, the base output chain's handle, and the
/// ownership marker/nonce stamped as the table comment at create time. A
/// delete-and-recreate of a same-shaped table yields DIFFERENT handles (nft
/// hands out monotonically increasing handles), and a foreign table cannot
/// carry our random marker, so binding readiness and teardown to this tuple —
/// not to the name — is what makes "same-shape replacement withdraws readiness"
/// and "release deletes only the exact owned object, never by name" true.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CastleTableOwnership {
    /// nft-assigned handle of the owned `inet sanctuary-castle` table.
    pub table_handle: u64,
    /// nft-assigned handle of the owned base `output` chain.
    pub base_chain_handle: u64,
    /// The full ownership marker (`OWNER_MARKER_PREFIX` + nonce) stamped as the
    /// table comment at create time and recorded in the ownership journal.
    pub marker: String,
}

#[cfg(target_os = "linux")]
static ACTIVE_RUNTIME_OWNERSHIP: OnceLock<Mutex<Option<CastleTableOwnership>>> = OnceLock::new();

#[cfg(target_os = "linux")]
fn runtime_ownership() -> &'static Mutex<Option<CastleTableOwnership>> {
    ACTIVE_RUNTIME_OWNERSHIP.get_or_init(|| Mutex::new(None))
}

/// Bind subsequent production agent mutations to the exact authenticated
/// table identity acquired through the host lock + ownership journal.
#[cfg(target_os = "linux")]
pub(crate) fn activate_runtime_ownership(
    ownership: &CastleTableOwnership,
) -> Result<(), NftablesError> {
    let mut guard = runtime_ownership().lock().map_err(|_| {
        NftablesError::InvocationFailed("runtime ownership state is poisoned".to_string())
    })?;
    match guard.as_ref() {
        Some(active) if active != ownership => Err(NftablesError::ForeignState(
            "a different nft runtime identity is already active in this process".to_string(),
        )),
        _ => {
            *guard = Some(ownership.clone());
            Ok(())
        }
    }
}

/// Test-only reset of the process-global authenticated-ownership latch.
///
/// This seam exists because `ACTIVE_RUNTIME_OWNERSHIP` models a property a real
/// daemon has for its whole life: a production process acquires ONE runtime
/// identity at boot and never clears it, so `activate_runtime_ownership`
/// deliberately refuses a second, different identity in the same process. A test
/// BINARY, however, drives the acquisition path many times in one process; the
/// second boot would otherwise hit that refusal ("a different nft runtime
/// identity is already active in this process") even though each boot is a
/// distinct, legitimate daemon lifetime. Clearing the latch here lets each test
/// start from the same clean process state a freshly-exec'd daemon would have.
/// Compiled ONLY under `--features test-isolation`; a release build has no way to
/// clear the latch, exactly like production. Analogous to the kernel-lock poison
/// reset seam.
#[cfg(all(target_os = "linux", feature = "test-isolation"))]
pub fn reset_runtime_ownership_for_tests() {
    // Recover a poisoned lock rather than panic: a prior failed test must not
    // convert this reset into a cascade that masks the real failure.
    let mut guard = runtime_ownership()
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    *guard = None;
}

/// Non-Linux counterpart of the reset seam above: there is no nft runtime
/// ownership latch off Linux, so there is nothing to clear.
///
/// It exists so that `tests/isolation/mod.rs` -- the ONE shared guard every
/// isolation-gated suite installs -- can call the seam unconditionally.
/// `integration_manifest_and_drain` is gated on `test-isolation` and also RUNS ON
/// MACOS (its assertions are portable), and the crate README documents
/// `cargo test --features test-isolation` as the local macOS command. Without
/// this arm that documented command fails to COMPILE with "cannot find function
/// in this scope", while Linux CI stays green: the failure appears only off the
/// platform CI covers, which is the hardest place to read it. Keeping the arm
/// here rather than a `cfg` at the call site means the next caller of the seam
/// inherits the fix instead of rediscovering the break.
#[cfg(all(not(target_os = "linux"), feature = "test-isolation"))]
pub fn reset_runtime_ownership_for_tests() {}

/// Prove the live table is still exactly this process's owned object BEFORE a
/// privileged agent mutation touches it.
///
/// `fortress_id` is the seal domain the caller is about to emit under, so a
/// pre-existing binding sealed under a DIFFERENT fortress fails here. The uid is
/// deliberately NOT compared: this is a precondition on the object being
/// mutated, and the caller may legitimately be replacing an older uid binding.
/// The trusted manifest comparison happens on the reclaim/adoption and health
/// paths, which read the CURRENT snapshot; the next health poll after this
/// mutation is that comparison.
#[cfg(target_os = "linux")]
fn verify_active_runtime_ownership(fortress_id: &str) -> Result<(), NftablesError> {
    if castle_table() != CASTLE_TABLE {
        // The integration-test namespace has no production journal. Its
        // isolation prefix and test-build mutation guard are the boundary.
        return Ok(());
    }
    let active = runtime_ownership()
        .lock()
        .map_err(|_| {
            NftablesError::InvocationFailed("runtime ownership state is poisoned".to_string())
        })?
        .clone()
        .ok_or_else(|| {
            NftablesError::ForeignState(
                "production agent mutation has no authenticated active ownership identity"
                    .to_string(),
            )
        })?;
    verify_owned_castle_table(
        &active,
        &ExpectedAgentBinding::SealOnly {
            fortress_id: fortress_id.to_string(),
        },
    )
}

/// A single nftables rule fragment generated from a PolicySnapshot rule.
#[derive(Debug, Clone)]
pub struct NftRuleFragment {
    /// The allowlist rule id this fragment was generated from.
    pub rule_id: String,
    /// nft rule expression (e.g., `ip daddr 1.2.3.4 tcp dport 443 accept`).
    pub nft_expr: String,
}

/// Translate a PolicySnapshot into nftables rule fragments for one agent.
/// The fragments are installed inside a per-agent chain within the
/// `sanctuary-castle` table. The chain ends with a `queue num 0` verdict
/// for any unmatched traffic (NFQUEUE with FAIL_OPEN explicitly off).
///
/// `agent_uid` is the uid the SIGNED manifest binds this agent to
/// (`agent_origin.agent_uid` in `src/manifest/verify.rs`), never a value read
/// from local configuration. It is emitted NUMERICALLY, never as an account
/// name: nft renders `meta skuid` through a uid symbol table, and the ownership
/// parser accepts only an integer, so a name in either the text or the JSON
/// listing would read a legitimate rule as foreign. Numeric emission is the one
/// half of that this daemon controls; the listing form is probed per nftables
/// version before the shape is trusted.
///
/// The trailing unconditional `drop` is the chain's fail-closed tail, but note
/// that it is not what the live guarantee rests on: the `queue num 0` above it
/// is emitted WITHOUT `bypass`, so an unreachable or unbound NFQUEUE drops the
/// packet in the kernel rather than releasing it.
pub fn build_agent_ruleset(agent_id: &str, agent_uid: u32, rules: &[NftRuleFragment]) -> String {
    let chain_name = agent_chain_name(agent_id);
    let castle_table = castle_table();
    let agent_mark = crate::nfqueue::register_agent_mark(agent_id);
    let mut script = String::new();
    // Atomic replace: flush the chain then re-add all rules.
    script.push_str(&format!(
        "flush chain {CASTLE_FAMILY} {castle_table} {chain_name}\n"
    ));
    // Static fragments are intentionally ignored. All signed rule semantics
    // execute in the ordered Rust evaluator behind the one NFQUEUE rule below.
    // Keeping this parameter during the API migration avoids a broad caller
    // break while removing raw fragment text from the privileged script.
    let _ = rules;
    // Default: send unmatched traffic to NFQUEUE 0 for userspace verdict.
    // Per scope-lock section 1: `queue num 0` without `bypass` flag.
    script.push_str(&format!(
        "add rule {CASTLE_FAMILY} {castle_table} {chain_name} \
         meta skuid {agent_uid} \
         meta mark set 0x{agent_mark:08x} queue num 0\n\
         add rule {CASTLE_FAMILY} {castle_table} {chain_name} drop\n"
    ));
    script
}

/// Build the jump rule that routes an agent's uid-owned packets into its
/// per-agent chain in the `sanctuary-castle` output chain. Pure helper: emits
/// the nft rule string only; callers shell out to apply it.
///
/// The base `output` chain created by [`install_castle_table`] is hooked
/// into netfilter (`type filter hook output priority 0`) but has no rules
/// of its own. Per-agent chains are non-base chains and stay dead until
/// something jumps to them. This helper produces the `goto agent_<id>`
/// rule that gates entry into the per-agent chain on `meta skuid <uid>`:
/// only packets whose socket carries the agent's uid transit the per-agent
/// rules. Every other packet in the operator's host (browser, OS daemons,
/// the operator's other apps) flows past the jump and is allowed by the base
/// chain's `policy accept`.
///
/// INVARIANT: the verdict is `goto`, not `jump`. `goto` is TERMINATING, so
/// control never returns to the accept-policy base chain after the per-agent
/// chain runs; a `jump` would fall back through to `policy accept` and silently
/// undo the per-agent decision. `validate_owned_jump_expr` pins the same verb on
/// the parse side.
pub fn build_agent_jump_rule(agent_id: &str, agent_uid: u32) -> String {
    let chain_name = agent_chain_name(agent_id);
    let castle_table = castle_table();
    format!(
        "add rule {CASTLE_FAMILY} {castle_table} output \
         meta skuid {agent_uid} goto {chain_name}"
    )
}

/// Build a fail-closed per-agent chain body: one unconditional `drop`.
///
/// Used to park an agent's chain at deny while its binding is being replaced, so
/// the window between "old body flushed" and "new body installed" can never be a
/// window where the agent's packets fall through to `policy accept`. The body
/// carries NO uid match and therefore NO seal — there is nothing to seal, and
/// `parse_owned_table_inventory` refuses a fail-closed body that carries one.
pub fn build_agent_fail_closed_ruleset(agent_id: &str) -> String {
    let chain_name = agent_chain_name(agent_id);
    let castle_table = castle_table();
    format!(
        "flush chain {CASTLE_FAMILY} {castle_table} {chain_name}\n\
         add rule {CASTLE_FAMILY} {castle_table} {chain_name} drop\n"
    )
}

/// Derive a sanitized chain name from an agent id.
pub(crate) fn agent_chain_name(agent_id: &str) -> String {
    let max_component_len = NFT_CHAIN_MAX_LEN - AGENT_CHAIN_PREFIX.len();
    let encoded = crate::identity::encode_agent_component(agent_id, max_component_len);
    format!("{AGENT_CHAIN_PREFIX}{encoded}")
}

// ---- nft binary resolution (cross-platform, PATH-free) --------------------
//
// A root daemon that activates nftables MUST resolve its enforcement binary by
// DIRECT absolute-path existence/executable checks, never through a PATH search
// or `which`: PATH is attacker-influenceable and a wrong `nft` on it would let a
// non-root-controlled binary run with the daemon's privilege. (blocker 9) These
// helpers are cross-platform + pure over an injected probe so the "absolute
// only, no PATH fallback" rule is unit-testable on the macOS dev host too.

/// Absolute nft locations, checked in order. Deliberately contains NO bare
/// `nft` entry: there is no PATH fallback. Must stay absolute-only; a bare name
/// here would reintroduce the PATH-resolution hazard this design removes.
///
/// The three entries cover common shipping layouts: `/usr/sbin/nft` and
/// `/sbin/nft` are the Debian/Ubuntu/Fedora
/// locations (nft is an sbin admin tool there), and `/usr/bin/nft` is where
/// Arch Linux — and the Arch-derived Omarchy — install it, since Arch places
/// nftables under `/usr/bin` (its usr-merge unifies `sbin` into `bin`). Adding
/// the Arch path makes Arch/Omarchy discoverable rather than silently failing
/// binary resolution. This is path compatibility, not a version-support claim:
/// enforcement also requires table-comment and JSON-comment support, and an
/// incompatible nft build fails activation closed. All three paths are absolute,
/// so the no-PATH-search contract is unchanged.
///
/// The nft-resolution helpers are production-used only on Linux (the `linux`
/// module below), but unit-tested on every host, so they are gated to
/// `any(target_os = "linux", test)`: on a non-Linux, non-test library build
/// they have no consumer and would otherwise trip `clippy -D warnings` as dead
/// code. Keep this cfg in lockstep with `is_executable_file` and
/// `resolve_nft_binary` — the tests exercise all three together.
#[cfg(any(target_os = "linux", test))]
pub(crate) const NFT_ABSOLUTE_PATHS: [&str; 3] = ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"];

/// True iff `path` is a regular file with at least one execute bit set. The nft
/// binary is selected by this direct check, never a PATH lookup.
#[cfg(all(unix, any(target_os = "linux", test)))]
pub(crate) fn is_executable_file(path: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(meta) => meta.is_file() && (meta.permissions().mode() & 0o111 != 0),
        Err(_) => false,
    }
}

#[cfg(all(not(unix), any(target_os = "linux", test)))]
pub(crate) fn is_executable_file(path: &str) -> bool {
    std::path::Path::new(path).is_file()
}

/// Resolve the nft binary to the first absolute candidate that exists and is
/// executable. Pure over the candidate list + an injected probe so the
/// no-PATH-fallback contract is testable without a real `/usr/sbin/nft`.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn resolve_nft_binary(
    candidates: &[&'static str],
    is_exec: impl Fn(&str) -> bool,
) -> Option<&'static str> {
    candidates
        .iter()
        .copied()
        .find(|&candidate| is_exec(candidate))
}

// ---- Linux implementations ------------------------------------------------

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::process::{Child, Command, Output};
    use std::time::Duration;

    const NFT_COMMAND_TIMEOUT: Duration = Duration::from_secs(2);

    fn wait_nft_bounded(child: Child) -> Result<Output, NftablesError> {
        let pid = child.id();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let waiter = std::thread::spawn(move || {
            let _ = tx.send(child.wait_with_output());
        });
        match rx.recv_timeout(NFT_COMMAND_TIMEOUT) {
            Ok(result) => {
                let _ = waiter.join();
                result.map_err(|err| NftablesError::InvocationFailed(err.to_string()))
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // Absolute binary, direct child: terminate the process whose
                // bounded output waiter we own, then join it so no detached nft
                // worker survives a control-path timeout.
                unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
                let result = rx.recv().map_err(|err| {
                    NftablesError::InvocationFailed(format!(
                        "nft timed out and waiter result was lost: {err}"
                    ))
                })?;
                let _ = waiter.join();
                let _ = result;
                Err(NftablesError::InvocationFailed(format!(
                    "nft invocation exceeded {}ms deadline",
                    NFT_COMMAND_TIMEOUT.as_millis()
                )))
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                let _ = waiter.join();
                Err(NftablesError::InvocationFailed(
                    "nft output waiter disconnected".to_string(),
                ))
            }
        }
    }

    /// Locate the `nft` binary by DIRECT absolute-path existence/executable
    /// check. NO PATH search, NO `which`: a PATH fallback is the exact hazard
    /// removed in blocker 9, so a missing absolute binary is a hard error, never
    /// a silent degrade to a bare `nft` resolved through PATH.
    fn nft_path() -> Result<&'static str, NftablesError> {
        super::resolve_nft_binary(&super::NFT_ABSOLUTE_PATHS, super::is_executable_file).ok_or_else(
            || {
                NftablesError::BinaryMissing(
                    "nft binary not found at /usr/sbin/nft, /sbin/nft, or /usr/bin/nft \
                     (no PATH fallback)"
                        .to_string(),
                )
            },
        )
    }

    /// Refuse to execute any `nft` command against the PRODUCTION table from a
    /// build that carries the test-isolation seams.
    ///
    /// This is the structural half of AGENTS.md's "the operator's machine is not
    /// a fixture". A convention ("remember to isolate") is what failed: the
    /// activation suite ran `nft delete table inet sanctuary-castle` on every
    /// setup, deleting the operator's LIVE enforcement table on any Linux host
    /// where `cargo test` ran. With this guard, a test build that forgot to call
    /// `use_isolated_castle_table` gets a LOUD error instead of silently mutating
    /// host state, and the failure names the fix.
    ///
    /// A production build has neither `cfg(test)` nor `feature = "test-isolation"`,
    /// so this compiles to nothing there and the shipped daemon is unchanged.
    #[cfg(any(test, feature = "test-isolation"))]
    fn refuse_production_table_under_test() -> Result<(), NftablesError> {
        // `castle_table()` RESOLVES as it reads. Consulting a non-resolving
        // predicate here would let the very first nft call of a process slip
        // through (nothing resolved yet -> "not production" -> pass) and only
        // then resolve to the production name.
        if super::castle_table() == super::CASTLE_TABLE {
            return Err(NftablesError::InvocationFailed(format!(
                "refusing to run nft against the PRODUCTION table `{}` from a \
                 test-isolation build: call nftables::use_isolated_castle_table(\"{}<tag>\") \
                 before any nftables call so this run cannot touch operator state",
                super::CASTLE_TABLE,
                super::ISOLATED_TABLE_PREFIX
            )));
        }
        Ok(())
    }

    #[cfg(not(any(test, feature = "test-isolation")))]
    fn refuse_production_table_under_test() -> Result<(), NftablesError> {
        Ok(())
    }

    fn run_nft(args: &[&str]) -> Result<String, NftablesError> {
        refuse_production_table_under_test()?;
        let nft = nft_path()?;
        let child = Command::new(nft)
            .env("LC_ALL", "C")
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| NftablesError::InvocationFailed(e.to_string()))?;
        let output = wait_nft_bounded(child)?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NftablesError::InvocationFailed(format!(
                "nft {} exited {}: {}",
                args.join(" "),
                output.status,
                stderr.trim()
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn run_nft_stdin(script: &str) -> Result<(), NftablesError> {
        refuse_production_table_under_test()?;
        let nft = nft_path()?;
        let mut child = Command::new(nft)
            .env("LC_ALL", "C")
            .arg("-f")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| NftablesError::InvocationFailed(e.to_string()))?;
        use std::io::Write;
        if let Some(stdin) = child.stdin.as_mut() {
            stdin
                .write_all(script.as_bytes())
                .map_err(|e| NftablesError::InvocationFailed(e.to_string()))?;
        }
        // Closing stdin is required before waiting; otherwise nft correctly
        // waits forever for more script bytes.
        drop(child.stdin.take());
        let output = wait_nft_bounded(child)?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NftablesError::InvocationFailed(format!(
                "nft -f - exited {}: {}",
                output.status,
                stderr.trim()
            )));
        }
        Ok(())
    }

    /// Generate a fresh ownership marker (`OWNER_MARKER_PREFIX` + a 128-bit hex
    /// nonce) for the idempotent installer. Mirrors the production acquisition
    /// path's `new_owner_marker` (runtime_providers.rs) so a table this helper
    /// creates is indistinguishable from a real owned table to the load path.
    fn fresh_install_owner_marker() -> Result<String, NftablesError> {
        use std::io::Read;
        let mut nonce = [0u8; 16];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut nonce))
            .map_err(|err| {
                NftablesError::InvocationFailed(format!(
                    "could not read /dev/urandom for the install ownership marker: {err}"
                ))
            })?;
        Ok(format!("{}{}", OWNER_MARKER_PREFIX, hex::encode(nonce)))
    }

    pub fn install_castle_table_impl() -> Result<(), NftablesError> {
        let castle_table = castle_table();
        // Invariant: the tightened load path (`load_agent_ruleset` ->
        // `capture_owned_castle_table_impl_from_live_inventory` ->
        // `parse_owned_table_identity`) refuses any owned table whose comment is
        // not an `OWNER_MARKER_PREFIX` ownership marker. This idempotent installer
        // therefore stamps a marker at create time, exactly as the production
        // acquisition path does via `build_create_castle_table_script`, instead of
        // a bare unmarked `add table` the load path would reject as ForeignState.
        // A table this helper leaves behind is always a validly-marked owned
        // object, so the agent-management / test load path exercises the real
        // capture -> parse contract rather than a shape production can never emit.
        if !table_exists_impl()? {
            let marker = fresh_install_owner_marker()?;
            // Table + base output chain land in one `create` transaction WITH the
            // marker comment. `create` is fail-on-exists, but we only reach it when
            // the table is absent (checked just above); this helper is the
            // single-threaded test / agent-management path, so a racing writer is
            // out of scope (the ACQUISITION path uses the host-lock-guarded
            // `create_castle_table_exclusive_impl`).
            run_nft_stdin(&super::build_create_castle_table_script(&marker))?;
        } else {
            // Idempotent: the marked table already exists. Ensure the base output
            // chain is present without disturbing the marker; `add chain` is a
            // no-op when the chain already exists.
            let chain_script = format!(
                "add chain {CASTLE_FAMILY} {castle_table} output \
                 {{ type filter hook output priority 0 ; policy accept ; }}\n"
            );
            let _ = run_nft_stdin(&chain_script);
        }
        Ok(())
    }

    /// GF1 deny-all safety net (the load-bearing fail-closed fix).
    ///
    /// Force the owned scopes to a fail-CLOSED state in ONE atomic `nft -f`
    /// transaction: recreate `<castle_table>` from scratch carrying a single
    /// base output chain whose default `policy` is `drop`. Whatever was present
    /// -- an empty base with `policy accept`, a full live-agent ruleset, an
    /// externally mutated/drifted chain, a drifted `accept` rule in the base
    /// chain, or nothing at all -- is replaced by a hooked output chain that
    /// DROPS every packet by default and carries no `accept` rule. The whole
    /// file is one atomic transaction, so the kernel never observes the
    /// intermediate deleted/empty state: there is NO fail-open window between
    /// tearing the old state down and the drop policy taking effect.
    ///
    /// The `add table` before the `delete table` makes the `delete` succeed even
    /// when the table is already gone (an external `nft delete table` while
    /// agents are live): add-then-delete-then-add yields a guaranteed-fresh table
    /// in both the absent and present cases, with no leftover agent chains/jumps.
    ///
    /// This is deliberately NOT a captured owned table: it carries `policy drop`,
    /// while the owned-table parser (`parse_owned_table_inventory`) requires
    /// `policy accept`, so a caller installs this and then REFUSES readiness
    /// rather than presenting it as a verified wall. Its sole guarantee is that
    /// owned-table LOSS or DRIFT can never leave `policy accept` in force for a
    /// live agent. Contract: Linux_Enforcement_Sprint_Architecture failure table
    /// ("Owned nft table flushed | Protected agents block; repair deny-all
    /// first") and product item 6 (external nftables mutation never creates a
    /// fail-open window). Callers: the reclaim/acquire path in
    /// `runtime_providers.rs` on owned-table LOSS and on captured-identity DRIFT,
    /// and the runtime health path on detected loss (GF1.3).
    ///
    /// GF1.4 threat-boundary note (assessed, inherent): the `delete table` here
    /// removes OUR named table by NAME. If a foreign table raced into the
    /// `sanctuary-castle` name in the sub-millisecond window between a caller's
    /// `table_exists()==false` observation and this transaction, that foreign
    /// table is replaced by our `policy drop` net. This is INHERENT to the
    /// CAP_NET_ADMIN threat model and is NOT a fail-open regression: (a) the
    /// replacement is fail-CLOSED (`policy drop`, no accept), so no traffic
    /// escapes; (b) the caller holds the host ownership lock and, on the reclaim
    /// paths, an authenticated this-boot ownership proof for this exact name, so
    /// the name is ours to force to deny-all; (c) a root actor racing nft cannot
    /// be defeated by any userspace check -- re-checking existence and refusing
    /// would REINTRODUCE a fail-open window (no drop table installed), the exact
    /// defect this net exists to prevent. The safety net's contract is "guarantee
    /// deny-all regardless of what currently holds the name," so add-delete-add is
    /// deliberate, not a bug to be narrowed.
    pub fn install_deny_all_safety_net_impl(scope: &SafetyNetScope) -> Result<(), NftablesError> {
        // The rule text, and above all the rule ORDER, comes from the shared pure
        // builder so the transaction this installs is byte-identical to the one
        // the unit tests assert. Must match `build_deny_all_safety_net_script`.
        let script = super::build_deny_all_safety_net_script(scope);
        run_nft_stdin(&script).map_err(|err| {
            let scope_text = match scope {
                SafetyNetScope::Identity(set) => {
                    format!("the confined identity {:?}", set.uids())
                }
                SafetyNetScope::HostWide => "every uid on this host".to_string(),
            };
            NftablesError::InvocationFailed(format!(
                "failed to install the deny-all safety net for {scope_text} (kernel egress \
                 state for the owned scopes may be indeterminate): {err}"
            ))
        })
    }

    /// GF1.1: whether the LIVE `sanctuary-castle` table is exactly this daemon's
    /// deny-all safety net (see [`super::is_deny_all_safety_net_json`]). Absence
    /// or an nft error reads as "not the net" (false / propagated error), so a
    /// caller only ever recovers on a positively-recognized fail-closed net.
    pub fn live_table_is_deny_all_safety_net_impl() -> Result<bool, NftablesError> {
        // FAIL CLOSED on the recogniser's inputs: without the host's configured
        // overflow uid the member revalidation cannot run, and an unrecognised
        // table is the conservative answer (the caller neither resets nor deletes
        // it). Must match the three-refusal contract in `crate::safety_net_uid`.
        let overflow = match HostOverflowUid::from_host() {
            Ok(value) => value,
            Err(err) => {
                return Err(NftablesError::InvocationFailed(format!(
                    "cannot classify the live table without this host's configured \
                     kernel.overflowuid: {err}"
                )))
            }
        };
        match run_nft(&["-j", "list", "table", CASTLE_FAMILY, castle_table()]) {
            Ok(json) => Ok(super::is_deny_all_safety_net_json(&json, overflow)),
            Err(NftablesError::InvocationFailed(msg))
                if msg.contains("No such file or directory") || msg.contains("does not exist") =>
            {
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// Strict, fresh coverage for the scope whose installation just failed.
    pub fn live_net_covers_attempt_impl(scope: &SafetyNetScope) -> Result<bool, NftablesError> {
        let overflow = HostOverflowUid::from_host().map_err(|e| {
            NftablesError::InvocationFailed(format!(
                "cannot classify live safety net without kernel.overflowuid: {e}"
            ))
        })?;
        let json = run_nft(&["-j", "list", "table", CASTLE_FAMILY, castle_table()])?;
        Ok(super::deny_all_net_covers_scope_json(
            &json, overflow, scope,
        ))
    }

    /// List the live castle table as `nft -j` JSON, or `None` when it is absent.
    ///
    /// FAILURE-MODE NOTE: nft reports an absent table as an invocation failure whose
    /// stderr names the missing file or object, so absence must be recognised from
    /// that text and mapped to `None`. Treating it as an error would make the safety
    /// net read "no table" as "unreadable" and lose source (c) on every fresh host.
    /// Must match the same recognition in `live_table_is_deny_all_safety_net_impl`.
    pub fn list_castle_table_json_impl() -> Result<Option<String>, NftablesError> {
        match run_nft(&["-j", "list", "table", CASTLE_FAMILY, castle_table()]) {
            Ok(json) => Ok(Some(json)),
            Err(NftablesError::InvocationFailed(msg))
                if msg.contains("No such file or directory") || msg.contains("does not exist") =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// D3: fetch the live castle table's raw JSON inventory using the existing
    /// optional-table read, treating an absent table as a failed recovery probe.
    /// A caller combining a recogniser answer with a second, independent property
    /// (the disarm `ReclaimOwned` arm's comment-key check) reads both off this
    /// ONE inventory rather than taking a further kernel snapshot. Unlike the
    /// recogniser's own wrapper, absence here is an ERROR, not `Ok(false)`: a
    /// caller reaching for the raw inventory already knows a table is present
    /// from its own prior state, so a missing table is a genuine race to
    /// surface, not an "absence reads as not-the-net" case.
    pub fn live_castle_table_json_impl() -> Result<String, NftablesError> {
        list_castle_table_json_impl()?.ok_or_else(|| {
            NftablesError::InvocationFailed(
                "castle table disappeared before the disarm recovery probe".to_string(),
            )
        })
    }

    /// GF1.1 recovery: atomically replace the deny-all safety net with a FRESH
    /// owned table (base output chain `policy accept`, stamped `new_marker`) in ONE
    /// `nft -f` transaction. `add`->`delete`->`create` means the kernel transitions
    /// directly from the `policy drop` net to the owned table with no intermediate
    /// absent/`accept`-without-the-owned-shape state: deny-all is held until the
    /// owned wall is up. Used only after `live_table_is_deny_all_safety_net_impl`
    /// has proven the current table is our own net AND the authenticated journal is
    /// `Preparing` for this boot (a create-failure that ReArmLostOwned armed); no
    /// agents exist in that state, so no per-agent jump is lost.
    pub fn atomic_reset_deny_all_net_to_fresh_owned_impl(
        new_marker: &str,
    ) -> Result<(), NftablesError> {
        if new_marker.contains('"') || new_marker.contains('\n') || new_marker.contains('\\') {
            return Err(NftablesError::InvocationFailed(
                "ownership marker contains characters unsafe for an nft comment".to_string(),
            ));
        }
        let castle_table = castle_table();
        // add (ensure exists) -> delete (remove the net) -> create fresh owned
        // table + base output chain, policy ACCEPT, all in one atomic transaction.
        let script = format!(
            "add table {CASTLE_FAMILY} {castle_table}\n\
             delete table {CASTLE_FAMILY} {castle_table}\n\
             create table {CASTLE_FAMILY} {castle_table} {{ comment \"{new_marker}\" ; }}\n\
             create chain {CASTLE_FAMILY} {castle_table} output \
             {{ type filter hook output priority 0 ; policy accept ; }}\n"
        );
        run_nft_stdin(&script).map_err(|err| {
            NftablesError::InvocationFailed(format!(
                "failed to atomically reset the deny-all net to a fresh owned table: {err}"
            ))
        })
    }

    /// GF1.2 last-resort escalation: delete the `sanctuary-castle` table by NAME
    /// so no live `policy accept` castle path can remain when the deny-all net
    /// itself could not be installed. `add`->`delete` is idempotent (succeeds
    /// whether or not the table is present). Used ONLY on the reclaim DRIFT path,
    /// where the caller holds the host lock and an authenticated this-boot
    /// ownership proof for this exact name, after `install_deny_all_safety_net`
    /// has already FAILED; the daemon then refuses readiness, so no agent is
    /// launched behind the (now table-less) host.
    pub fn force_delete_castle_table_by_name_impl() -> Result<(), NftablesError> {
        let castle_table = castle_table();
        let script = format!(
            "add table {CASTLE_FAMILY} {castle_table}\n\
             delete table {CASTLE_FAMILY} {castle_table}\n"
        );
        run_nft_stdin(&script).map_err(|err| {
            NftablesError::InvocationFailed(format!(
                "failed to force-delete the drifted sanctuary-castle table by name: {err}"
            ))
        })
    }

    /// Create the `sanctuary-castle` table AND its exact base output chain in
    /// ONE atomic `nft -f` transaction using nft's FAIL-ON-EXISTS `create`
    /// verbs, propagating any error. (blocker 1)
    ///
    /// The verbs are `create table` / `create chain`, NOT the idempotent `add`.
    /// `create` fails the whole transaction if the object already exists, so a
    /// `sanctuary-castle` table that appears AFTER the caller's preflight
    /// existence check (a racing writer, a foreign table) makes this call fail
    /// rather than silently adopt or mutate it. `add` would have quietly
    /// succeeded against that pre-existing table — exactly the adoption the L2
    /// ownership model forbids. The table carries `marker` as its `comment` so
    /// the ownership can later be proven by nonce, not by name.
    ///
    /// Contract for the caller (the acquisition path): the host ownership lock
    /// is held AND the table has been confirmed ABSENT before this is called.
    /// Because table + chain land in a single `create` transaction, a partial
    /// install (table present, base chain missing) is impossible: nft applies
    /// the whole transaction or none of it.
    ///
    /// Failure-mode note: a raced foreign table that appears in the window
    /// between the caller's existence check and this call makes `create table`
    /// return a nonzero nft exit ("File exists"), surfaced here as
    /// `InvocationFailed`. The transaction was atomic, so this acquisition
    /// created NOTHING — it fails-before and never deletes the racer's table.
    pub fn create_castle_table_exclusive_impl(marker: &str) -> Result<(), NftablesError> {
        // Reject a marker that would break out of the nft comment string. The
        // marker is our own `OWNER_MARKER_PREFIX` + hex nonce, so this never
        // triggers in production; it is a defense-in-depth guard against a caller
        // passing an unexpected value into a shelled-out script.
        if marker.contains('"') || marker.contains('\n') || marker.contains('\\') {
            return Err(NftablesError::InvocationFailed(
                "ownership marker contains characters unsafe for an nft comment".to_string(),
            ));
        }
        run_nft_stdin(&super::build_create_castle_table_script(marker)).map_err(|err| {
            NftablesError::InvocationFailed(format!(
                "exclusive owned-table creation failed (Sanctuary requires nft table-comment and JSON-comment support): {err}"
            ))
        })
    }

    /// List `inet sanctuary-castle` as structured JSON and parse it into the
    /// EXACT owned identity, requiring the marker to equal `expected_marker`.
    /// Used right after [`create_castle_table_exclusive_impl`] to CAPTURE the
    /// handles this acquisition owns (blocker 3, the "capture/verify handles"
    /// step of prepare -> create -> capture -> finalize).
    pub fn capture_owned_castle_table_impl(
        expected_marker: &str,
    ) -> Result<CastleTableOwnership, NftablesError> {
        // `-a/--handle` is mandatory: libnftables omits handles from listings by
        // default, while the ownership parser deliberately requires both the
        // table and base-chain handles as part of the exact live identity.
        let json = run_nft(&["-a", "-j", "list", "table", CASTLE_FAMILY, castle_table()])?;
        // A table this daemon just created with `create table` holds ZERO agent
        // chains by construction, so any per-agent binding present here is
        // something this process did not install: refuse it rather than capture
        // an identity over state of unknown provenance.
        let owned =
            super::parse_owned_table_identity(&json, &super::ExpectedAgentBinding::NoneConfined)?;
        if owned.marker != expected_marker {
            return Err(NftablesError::ForeignState(format!(
                "captured table marker does not match the marker just written \
                 (expected {expected_marker}, found {})",
                owned.marker
            )));
        }
        Ok(owned)
    }

    /// Re-list the live table and require it to STILL be exactly the captured
    /// owned identity — same handles, same marker, same pristine shape. A
    /// delete/recreate (new handles), a mutation, an injected rule, an extra
    /// chain, or a marker change all fail here. (blocker 2)
    /// The handle-bearing listing the owned-table parser needs.
    ///
    /// `-a` is not optional here and is the reason this is a named helper rather
    /// than the plain `list_castle_table_json_impl`: without it nft omits the
    /// handles, and the parser would read a perfectly good owned table as having
    /// no table handle at all. Must match the argv in
    /// [`verify_owned_castle_table_impl`], whose parse this one mirrors.
    pub fn list_owned_castle_table_json_for_binding_set() -> Result<String, NftablesError> {
        run_nft(&["-a", "-j", "list", "table", CASTLE_FAMILY, castle_table()])
    }

    pub fn verify_owned_castle_table_impl(
        ownership: &CastleTableOwnership,
        expectation: &super::ExpectedAgentBinding,
    ) -> Result<Vec<String>, NftablesError> {
        let json = run_nft(&["-a", "-j", "list", "table", CASTLE_FAMILY, castle_table()])?;
        // This caller needs BOTH phases: it is a pre-mutation ownership
        // precondition, so a drifted binding must refuse. Must match the polarity
        // in `parse_owned_table_identity`.
        let live = match super::parse_owned_table_inventory_phases(&json, expectation)? {
            super::OwnedInventoryPhases::Verified(parsed) => parsed,
            super::OwnedInventoryPhases::UidMismatch { detail, .. } => {
                return Err(NftablesError::ForeignState(detail))
            }
        };
        if &live.ownership == ownership {
            Ok(live.agent_ids)
        } else {
            Err(NftablesError::ForeignState(format!(
                "sanctuary-castle table identity changed since acquisition \
                 (expected handles table={}/chain={} marker={}, found table={}/chain={} marker={}); \
                 a same-name replacement or mutation is not the owned object",
                ownership.table_handle,
                ownership.base_chain_handle,
                ownership.marker,
                live.ownership.table_handle,
                live.ownership.base_chain_handle,
                live.ownership.marker,
            )))
        }
    }

    /// Delete ONLY the exact captured owned table, using a HANDLE-qualified
    /// delete (`delete table inet handle <N>`), and only after re-verifying the
    /// live identity still matches. (blocker 2/3)
    ///
    /// If the live identity no longer matches (a foreign table replaced ours, or
    /// the shape changed), this REFUSES rather than deleting: we never delete a
    /// `sanctuary-castle` table by name once its identity has drifted, so a
    /// foreign object that squatted the name is left intact. Deleting by the
    /// captured handle (not by name) means that even if a foreign table now
    /// holds the name, our stale handle either no longer resolves (nft errors)
    /// or resolves to a different object we already refused above.
    pub fn remove_owned_castle_table_impl(
        ownership: &CastleTableOwnership,
        expectation: &super::ExpectedAgentBinding,
    ) -> Result<(), NftablesError> {
        // Prove the live table is still exactly ours before removing anything.
        verify_owned_castle_table_impl(ownership, expectation)?;
        run_nft(&[
            "delete",
            "table",
            CASTLE_FAMILY,
            "handle",
            &ownership.table_handle.to_string(),
        ])
        .map(|_| ())
    }

    fn replace_agent_chain_and_jump_impl(
        id: &AgentRulesetId,
        ruleset_script: &str,
        binding: AgentUidBinding,
        fail_closed: bool,
    ) -> Result<(), NftablesError> {
        verify_active_runtime_ownership(&id.fortress_id)?;
        validate_agent_binding_input(id, binding)?;
        let expected_script = if fail_closed {
            build_agent_fail_closed_ruleset(&id.agent_id)
        } else {
            build_agent_ruleset(&id.agent_id, binding.agent_uid, &[])
        };
        if ruleset_script != expected_script {
            return Err(NftablesError::InvocationFailed(
                "agent ruleset must be the exact typed NFQUEUE-only lowering; raw nft fragments are forbidden"
                    .to_string(),
            ));
        }
        let chain_name = agent_chain_name(&id.agent_id);
        let castle_table = castle_table();
        let ownership = capture_owned_castle_table_impl_from_live_inventory(&id.fortress_id)?;
        let chain_comment = format!("{}:agent:{}", ownership.marker, id.agent_id);
        let rule_role = if fail_closed { "failclosed" } else { "queue" };
        // Seal the exact installed uid into the authenticated, marker-bound
        // comment of every rule that carries a `meta skuid` match (the
        // base-output jump always; the per-agent body only when it is the queued
        // uid match, NOT the fail-closed unconditional drop, which has no uid
        // match to seal). `parse_owned_table_inventory` recomputes this seal from
        // the live match value and refuses a rule whose uid was rewritten in
        // place. Must match the seal the parser recomputes; see `agent_uid_seal`.
        let uid_seal = super::agent_uid_seal(&id.fortress_id, &id.agent_id, binding.agent_uid);
        let queue_comment = if fail_closed {
            format!("{}:{rule_role}:{}", ownership.marker, id.agent_id)
        } else {
            format!(
                "{}:{rule_role}:{}{}{}",
                ownership.marker,
                id.agent_id,
                super::AGENT_UID_SEAL_INFIX,
                uid_seal
            )
        };
        let jump_comment = format!(
            "{}:jump:{}{}{}",
            ownership.marker,
            id.agent_id,
            super::AGENT_UID_SEAL_INFIX,
            uid_seal
        );
        let listing = match run_nft(&["-a", "list", "chain", CASTLE_FAMILY, castle_table, "output"])
        {
            Ok(s) => s,
            Err(NftablesError::InvocationFailed(msg))
                if msg.contains("No such file or directory") || msg.contains("does not exist") =>
            {
                String::new()
            }
            Err(e) => return Err(e),
        };
        let handles = parse_jump_rule_handles(&listing, &chain_name);

        let agent_rule = if fail_closed {
            format!("add rule {CASTLE_FAMILY} {castle_table} {chain_name} drop comment \"{queue_comment}\"\n")
        } else {
            let agent_mark = crate::nfqueue::register_agent_mark(&id.agent_id);
            let agent_uid = binding.agent_uid;
            format!(
                "add rule {CASTLE_FAMILY} {castle_table} {chain_name} meta skuid {agent_uid} meta mark set 0x{agent_mark:08x} queue num 0 comment \"{queue_comment}\"\n"
            )
        };
        // Chain creation/adoption, body replacement, stale-jump removal, and
        // the new jump land in one nft transaction. A crash can therefore
        // expose either the complete prior binding or the complete new one,
        // never an empty agent chain or a half-wired replacement.
        let mut script = format!(
            "add chain {CASTLE_FAMILY} {castle_table} {chain_name} {{ comment \"{chain_comment}\" ; }}\n\
             flush chain {CASTLE_FAMILY} {castle_table} {chain_name}\n{agent_rule}"
        );
        for handle in handles {
            script.push_str(&format!(
                "delete rule {CASTLE_FAMILY} {castle_table} output handle {handle}\n"
            ));
        }
        let rule = build_agent_jump_rule(&id.agent_id, binding.agent_uid);
        script.push_str(&format!("{rule} comment \"{jump_comment}\"\n"));
        run_nft_stdin(&script)
    }

    fn capture_owned_castle_table_impl_from_live_inventory(
        fortress_id: &str,
    ) -> Result<CastleTableOwnership, NftablesError> {
        let json = run_nft(&["-a", "-j", "list", "table", CASTLE_FAMILY, castle_table()])?;
        // Seal-only: this reads the marker off a table that may legitimately
        // already carry an older agent binding, on the way to REPLACING it. The
        // manifest-uid comparison belongs to the reclaim/adoption and health
        // paths, which hold the current snapshot.
        super::parse_owned_table_identity(
            &json,
            &ExpectedAgentBinding::SealOnly {
                fortress_id: fortress_id.to_string(),
            },
        )
    }

    fn validate_agent_binding_input(
        id: &AgentRulesetId,
        binding: AgentUidBinding,
    ) -> Result<(), NftablesError> {
        // INVARIANT: an agent id that cannot fit its own sealed comment must be
        // refused HERE, not by nft. `MAX_AGENT_ID_LEN` is derived from the
        // comment budget, so an over-long id would otherwise be caught only by an
        // opaque nft load-time rejection in the middle of the atomic transaction.
        if id.agent_id.is_empty()
            || id.agent_id.len() > MAX_AGENT_ID_LEN
            || !id
                .agent_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err(NftablesError::InvocationFailed(format!(
                "agent id is outside the typed nft identifier grammar or exceeds the \
                 {MAX_AGENT_ID_LEN}-byte sealed-comment budget"
            )));
        }
        // The fortress id is a SEAL INPUT, so an empty one would collapse the
        // seal's domain separation and let a rule sealed under one fortress
        // verify under another.
        if id.fortress_id.is_empty() {
            return Err(NftablesError::InvocationFailed(
                "agent ruleset id carries no fortress id; the uid seal has no domain".to_string(),
            ));
        }
        // INVARIANT: uid 0 is root and is never a confined agent, and a uid below
        // the manifest's `system_uid_allow_ceiling` is a SYSTEM account whose
        // egress this wall must not claim to gate. Both are already refused at
        // manifest admission (`confined_agent_uid_from_loaded_manifest` in
        // `src/policy.rs`); re-checking at the emission site means a caller that
        // reaches this function by any other route cannot seal a system uid into
        // a kernel rule. Must match the floors in that function.
        if binding.agent_uid < 1 || binding.agent_uid < binding.system_uid_allow_ceiling {
            return Err(NftablesError::InvocationFailed(format!(
                "agent uid {} is root or below the manifest system-uid allow ceiling {}",
                binding.agent_uid, binding.system_uid_allow_ceiling
            )));
        }
        // INVARIANT: the ceiling floor above STAYS and is not replaced by what
        // follows. The ceiling proves the uid is outside the system-daemon band;
        // these three refusals prove the uid names a single attestable principal
        // at all. They answer different questions, and a uid must clear both
        // before it is sealed into a kernel rule. Must match the same three
        // refusals at admission in `crate::policy::confined_agent_uid_from_loaded_manifest`
        // and the closed-set contract in `crate::safety_net_uid`.
        let overflow = HostOverflowUid::from_host().map_err(|err| {
            NftablesError::InvocationFailed(format!(
                "cannot seal an agent uid into a kernel rule without this host's configured \
                 kernel.overflowuid: {err}"
            ))
        })?;
        validate_safety_net_uid(binding.agent_uid, overflow).map_err(|err| {
            NftablesError::InvocationFailed(format!(
                "agent uid {} may not be sealed into a kernel rule: {err}",
                binding.agent_uid
            ))
        })?;
        Ok(())
    }

    pub fn load_agent_ruleset_impl(
        id: &AgentRulesetId,
        ruleset_script: &str,
        binding: AgentUidBinding,
    ) -> Result<(), NftablesError> {
        // Atomically replace the per-agent chain body and the base output jump
        // that reaches it. This keeps a policy reload from leaking a stale jump
        // bound to a superseded uid.
        replace_agent_chain_and_jump_impl(id, ruleset_script, binding, false)
    }

    pub fn load_agent_fail_closed_ruleset_impl(
        id: &AgentRulesetId,
        binding: AgentUidBinding,
    ) -> Result<(), NftablesError> {
        let ruleset_script = build_agent_fail_closed_ruleset(&id.agent_id);
        replace_agent_chain_and_jump_impl(id, &ruleset_script, binding, true)
    }

    pub fn remove_agent_ruleset_impl(id: &AgentRulesetId) -> Result<(), NftablesError> {
        super::verify_active_runtime_ownership(&id.fortress_id)?;
        let chain_name = agent_chain_name(&id.agent_id);
        let castle_table = castle_table();
        let listing = match run_nft(&["-a", "list", "chain", CASTLE_FAMILY, castle_table, "output"])
        {
            Ok(s) => s,
            Err(NftablesError::InvocationFailed(msg))
                if msg.contains("No such file or directory") || msg.contains("does not exist") =>
            {
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        // Jump deletion, chain flush, and chain deletion are atomic. This is
        // the inverse of replacement above and prevents restart from finding
        // a marker-bound chain without its required jump/body pair.
        let mut script = String::new();
        for handle in parse_jump_rule_handles(&listing, &chain_name) {
            script.push_str(&format!(
                "delete rule {CASTLE_FAMILY} {castle_table} output handle {handle}\n"
            ));
        }
        script.push_str(&format!(
            "flush chain {CASTLE_FAMILY} {castle_table} {chain_name}\n\
             delete chain {CASTLE_FAMILY} {castle_table} {chain_name}\n"
        ));
        run_nft_stdin(&script)
    }

    /// Install the jump rule from the base `output` chain into this agent's
    /// per-agent chain, gated on the cgroup-v2 socket match. Idempotent:
    /// any prior jump rule pointing at the same agent's chain is removed
    /// (handle-based delete) before the new rule is added. This lets the
    /// function double as both the fresh-install and policy-reload path
    /// without leaking stale jumps.
    pub fn install_agent_jump_rule_impl(
        id: &AgentRulesetId,
        binding: AgentUidBinding,
    ) -> Result<(), NftablesError> {
        // Drop any existing jump rule for this agent before adding a new
        // one. Failures during the lookup are not fatal here: a missing
        // base chain (table just created, nothing in output yet) returns
        // an error from `nft -a list chain`; the upcoming add will fail
        // with a clearer message if the table is genuinely absent.
        let _ = remove_agent_jump_rule_impl(id);
        let rule = build_agent_jump_rule(&id.agent_id, binding.agent_uid);
        let script = format!("{rule}\n");
        run_nft_stdin(&script)
    }

    /// Remove the jump rule from the base `output` chain that targets this
    /// agent's per-agent chain. Idempotent: zero matching rules returns
    /// `Ok(())` rather than an error so policy-reload code paths can call
    /// it unconditionally.
    pub fn remove_agent_jump_rule_impl(id: &AgentRulesetId) -> Result<(), NftablesError> {
        let chain_name = agent_chain_name(&id.agent_id);
        // `-a` annotates each rule with `# handle <N>`; we parse those
        // handles for any rule whose verdict targets our chain.
        let listing = match run_nft(&[
            "-a",
            "list",
            "chain",
            CASTLE_FAMILY,
            castle_table(),
            "output",
        ]) {
            Ok(s) => s,
            Err(NftablesError::InvocationFailed(msg))
                if msg.contains("No such file or directory") || msg.contains("does not exist") =>
            {
                // Base chain absent (table was deleted or never installed).
                // Treat as zero matching rules.
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        let handles = parse_jump_rule_handles(&listing, &chain_name);
        for handle in handles {
            run_nft(&[
                "delete",
                "rule",
                CASTLE_FAMILY,
                castle_table(),
                "output",
                "handle",
                &handle.to_string(),
            ])?;
        }
        Ok(())
    }

    /// Parse `nft -a list chain ... output` output, returning the handle
    /// integer for every rule whose verdict is `goto <chain_name>`. The
    /// match is token-precise (no substring match) so chain names that
    /// share a prefix (`agent_foo`, `agent_foo_bar`) do not collide.
    pub(super) fn parse_jump_rule_handles(listing: &str, chain_name: &str) -> Vec<u64> {
        let mut handles = Vec::new();
        for line in listing.lines() {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            // Find a `goto <chain_name>` token pair. nft also emits `jump`
            // for non-terminating verdicts; we only emit `goto` so we
            // restrict the match to that.
            let has_goto = tokens
                .iter()
                .enumerate()
                .any(|(i, tok)| *tok == "goto" && tokens.get(i + 1) == Some(&chain_name));
            if !has_goto {
                continue;
            }
            // Extract handle from "# handle <N>". `nft -a` always emits
            // both tokens together at the end of the rule line.
            if let Some(handle_idx) = tokens.iter().position(|t| *t == "handle") {
                if handle_idx > 0 && tokens[handle_idx - 1] == "#" {
                    if let Some(handle_tok) = tokens.get(handle_idx + 1) {
                        if let Ok(h) = handle_tok.parse::<u64>() {
                            handles.push(h);
                        }
                    }
                }
            }
        }
        handles
    }

    /// Agent ids visible as `agent_*` chain names.
    ///
    /// Returns bare ids, NOT [`AgentRulesetId`]: a chain listing carries no
    /// fortress id and no uid, so an `AgentRulesetId` synthesized here would be a
    /// half-empty identity a caller could mistake for a real binding. Callers
    /// that need the binding read it from the inventory parser.
    pub fn list_agent_rulesets_impl() -> Result<Vec<String>, NftablesError> {
        let output = run_nft(&["list", "chains", CASTLE_FAMILY])?;
        let mut results = Vec::new();
        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("chain agent_") {
                // Extract chain name between "chain " and the next space or '{'
                if let Some(name) = trimmed
                    .strip_prefix("chain ")
                    .and_then(|s| s.split_whitespace().next())
                {
                    if let Some(agent_id) = name.strip_prefix("agent_") {
                        results.push(agent_id.to_string());
                    }
                }
            }
        }
        Ok(results)
    }

    pub fn remove_castle_table_impl() -> Result<(), NftablesError> {
        run_nft(&["delete", "table", CASTLE_FAMILY, castle_table()]).map(|_| ())
    }

    pub fn table_exists_impl() -> Result<bool, NftablesError> {
        match run_nft(&["list", "table", CASTLE_FAMILY, castle_table()]) {
            Ok(_) => Ok(true),
            Err(NftablesError::InvocationFailed(msg))
                if msg.contains("No such file or directory") || msg.contains("does not exist") =>
            {
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    pub fn verify_castle_table_shape_impl() -> Result<(), NftablesError> {
        // List OUR table by exact family+name in STRUCTURED JSON (`nft -j`).
        // Absence is a hard error here: the readiness check runs right after the
        // table is created, so a missing table means the create silently did not
        // take. Structured parsing (not a substring scan) is what lets us tell a
        // base output chain from a same-named regular chain, and a chain in our
        // table from one in a foreign table. (blocker 2)
        let json = run_nft(&["-a", "-j", "list", "table", CASTLE_FAMILY, castle_table()])?;
        // A table that shares the `sanctuary-castle` name but lacks our exact
        // base-output-chain shape — or carries any foreign base chain — is
        // foreign/incompatible state (another owner, a hand-edited ruleset, a
        // leftover from an incompatible version); adopting it would enforce
        // through — or later clobber — a ruleset we do not own.
        if super::output_chain_shape_is_ours_json(&json) {
            Ok(())
        } else {
            Err(NftablesError::ForeignState(format!(
                "sanctuary-castle table does not have this daemon's exact base output chain \
                 (inet/sanctuary-castle output: type filter hook output priority 0 policy \
                 accept), or carries foreign base-chain state: {}",
                json.trim()
            )))
        }
    }
}

/// Whether an `nft -j list table inet sanctuary-castle` JSON document shows
/// EXACTLY this daemon's base output chain and no foreign base-chain state.
///
/// This is the STRUCTURED replacement for the old substring scan (blocker 2). A
/// substring match cannot distinguish a base chain from a same-named regular
/// chain, cannot tell a chain in OUR table from one in a foreign table (a
/// "split" shape), and can be fooled by comments or unrelated rules. Parsing the
/// nft JSON lets the check be tied to the exact fields.
///
/// Returns true only when a `chain` object exists with ALL of: `family` ==
/// `inet`, `table` == `sanctuary-castle`, `name` == `output`, `type` ==
/// `filter`, `hook` == `output`, `prio` == 0, `policy` == `accept`. It returns
/// FALSE — refuse — for every other shape: an unparseable or empty document
/// (unknown ownership), a table with no base chain, a base chain with the wrong
/// hook / type / priority / a `drop` policy, a chain in a different family or
/// table (split/foreign), or ANY additional base chain (one carrying a `hook`)
/// that is not this exact shape. Refuse is the safe default: absent,
/// indeterminate, and foreign all read as not-ours.
///
/// Pure and cross-platform so the foreign-table refusal is unit-testable without
/// a live kernel (see the adversarial-JSON tests below).
pub fn output_chain_shape_is_ours_json(json: &str) -> bool {
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(json) else {
        // Unparseable -> unknown ownership state -> refuse.
        return false;
    };
    let Some(items) = doc.get("nftables").and_then(|v| v.as_array()) else {
        return false;
    };
    let mut found_ours = false;
    for item in items {
        let Some(chain) = item.get("chain") else {
            continue;
        };
        // Only BASE chains carry a `hook`; a regular (non-base) chain has none.
        // A base chain is the only thing that can hook egress, so any base chain
        // present must be exactly ours — a foreign base chain is refusable state.
        let Some(hook) = chain.get("hook").and_then(|v| v.as_str()) else {
            continue;
        };
        let is_ours = chain.get("family").and_then(|v| v.as_str()) == Some(CASTLE_FAMILY)
            && chain.get("table").and_then(|v| v.as_str()) == Some(castle_table())
            && chain.get("name").and_then(|v| v.as_str()) == Some("output")
            && chain.get("type").and_then(|v| v.as_str()) == Some("filter")
            && hook == "output"
            && chain.get("prio").and_then(|v| v.as_i64()) == Some(0)
            && chain.get("policy").and_then(|v| v.as_str()) == Some("accept");
        if is_ours {
            found_ours = true;
        } else {
            // A base chain (has a hook) that is not exactly ours — wrong hook,
            // wrong priority, drop policy, or a split chain whose family/table
            // do not match — is foreign/incompatible state we must refuse rather
            // than enforce through or adopt.
            return false;
        }
    }
    found_ours
}

/// GF1.1/D2: whether an `nft -j list table inet sanctuary-castle` JSON document is
/// EXACTLY this daemon's deny-all safety net, in either of its two permanent
/// shapes, as `build_deny_all_safety_net_script` emits them.
///
/// Both shapes require ONE `inet/sanctuary-castle` table with NO table `comment`
/// key at all, and ONE base `output` chain (`type filter hook output priority 0`,
/// `policy drop`). They differ only in the rules:
///
///   * the V2 identity shape: exactly the three rules of `D1`, IN ORDER, each
///     carrying its own comment constant, with rule 1's and rule 3's uid sets
///     EQUAL, non-empty, and every member passing the shared three-refusal
///     validator;
///   * the V1 host-wide shape: zero rules.
///
/// Anything else is "not the net": refuse, never recover.
///
/// INVARIANT, why the table comment must be ABSENT and not merely
/// non-`OWNER_MARKER_PREFIX`: this predicate is what authorises the disarm verb's
/// recovery arm to DELETE a live table by name. `build_deny_all_safety_net_script`
/// stamps no table comment on either shape, so a `policy drop` table carrying ANY
/// comment was armed by something other than this daemon and must not be deleted
/// as if it were ours. Reading only the owner prefix here would accept a
/// zero-rule `policy drop` table with a foreign comment.
///
/// INVARIANT, why the members are revalidated: the installer type cannot produce
/// a set containing `0`, this host's `kernel.overflowuid` or `u32::MAX`, so a live
/// table whose set carries one of those was not armed by this daemon however
/// well-formed the rest of it looks. Accepting it would let the recovery arm
/// delete a table this daemon could not have installed. `overflow` is the host's
/// own configured value; a caller that cannot read it must treat the table as NOT
/// the net, which is the conservative side (no delete, no reset).
///
/// Residual, accepted and unchanged from v1: a foreign actor holding
/// `CAP_NET_ADMIN` can swap in an identical-shape table in the window between
/// this recognition and the caller's next transaction. That is the inherent bound
/// documented on `install_deny_all_safety_net_impl`, and it is fail-CLOSED either
/// way.
///
/// Pure and cross-platform so the recogniser is unit-testable without a kernel.
pub fn is_deny_all_safety_net_json(json: &str, overflow: HostOverflowUid) -> bool {
    recognized_net_json(json, overflow).is_some()
}

#[derive(Debug, PartialEq, Eq)]
enum RecognizedNet {
    HostWide,
    Identity(Vec<u32>),
}

/// Coverage uses the identical strict parser that authorizes disarm recognition.
pub fn deny_all_net_covers_scope_json(
    json: &str,
    overflow: HostOverflowUid,
    attempted: &SafetyNetScope,
) -> bool {
    match (recognized_net_json(json, overflow), attempted) {
        (Some(RecognizedNet::HostWide), _) => true,
        (Some(RecognizedNet::Identity(live)), SafetyNetScope::Identity(attempt)) => attempt
            .uids()
            .iter()
            .all(|uid| live.binary_search(uid).is_ok()),
        _ => false,
    }
}

fn recognized_net_json(json: &str, overflow: HostOverflowUid) -> Option<RecognizedNet> {
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(json) else {
        return None;
    };
    let items = doc.get("nftables").and_then(|v| v.as_array())?;
    let mut saw_table = false;
    let mut saw_drop_base_chain = false;
    let mut rules: Vec<&serde_json::Value> = Vec::new();
    for item in items {
        let obj = item.as_object()?;
        if obj.len() != 1 {
            return None;
        }
        for (kind, val) in obj {
            match kind.as_str() {
                "metainfo" => {}
                "table" => {
                    if saw_table {
                        return None; // more than one table object
                    }
                    let ours = val.get("family").and_then(|v| v.as_str()) == Some(CASTLE_FAMILY)
                        && val.get("name").and_then(|v| v.as_str()) == Some(castle_table());
                    // Neither net shape carries a table comment, so ANY comment
                    // here (owner-prefixed or foreign) means this is not our net.
                    let has_any_comment = val.get("comment").is_some();
                    if !ours || has_any_comment {
                        return None;
                    }
                    saw_table = true;
                }
                "chain" => {
                    if saw_drop_base_chain {
                        return None; // more than one chain
                    }
                    let is_deny_all_base = val.get("family").and_then(|v| v.as_str())
                        == Some(CASTLE_FAMILY)
                        && val.get("table").and_then(|v| v.as_str()) == Some(castle_table())
                        && val.get("name").and_then(|v| v.as_str()) == Some("output")
                        && val.get("type").and_then(|v| v.as_str()) == Some("filter")
                        && val.get("hook").and_then(|v| v.as_str()) == Some("output")
                        && val.get("prio").and_then(|v| v.as_i64()) == Some(0)
                        && val.get("policy").and_then(|v| v.as_str()) == Some("drop");
                    if !is_deny_all_base {
                        return None;
                    }
                    saw_drop_base_chain = true;
                }
                "rule" => {
                    let in_our_chain = val.get("family").and_then(|v| v.as_str())
                        == Some(CASTLE_FAMILY)
                        && val.get("table").and_then(|v| v.as_str()) == Some(castle_table())
                        && val.get("chain").and_then(|v| v.as_str()) == Some("output");
                    if !in_our_chain {
                        return None;
                    }
                    rules.push(val);
                }
                // An agent chain, set, map, flowtable, or any other object means
                // this is NOT the safety net in either shape.
                _ => return None,
            }
        }
    }
    if !(saw_table && saw_drop_base_chain) {
        return None;
    }
    match rules.len() {
        // V1 host-wide shape: zero rules under the drop policy.
        0 => Some(RecognizedNet::HostWide),
        // V2 identity shape: exactly the three rules, in order.
        NET_V2_RULE_COUNT => net_v2_rules_match(&rules, overflow).map(RecognizedNet::Identity),
        // One rule is a shape `build_deny_all_safety_net_script` never emits, and
        // a fourth rule is drift or injection.
        _ => None,
    }
}

/// Rules in the net's v2 identity shape. Named so the recogniser's arm reads as
/// "the three rules" rather than as a bare literal.
/// Must match the rule count `build_deny_all_safety_net_script` emits for
/// `SafetyNetScope::Identity`.
const NET_V2_RULE_COUNT: usize = 3;

/// Whether `rules` are EXACTLY the net's three v2 rules, in order.
///
/// INVARIANT: order is checked positionally, not by searching for each comment.
/// A table carrying the same three rules in a different order is a DIFFERENT
/// enforcement outcome (an accept ahead of the drop lets the agent out), so it
/// must be refused, which a comment-set comparison would not do.
fn net_v2_rules_match(rules: &[&serde_json::Value], overflow: HostOverflowUid) -> Option<Vec<u32>> {
    let denied =
        rule_skuid_set_with_verdict(rules[0], "==", "drop", NET_RULE_COMMENT_IDENTITY, overflow)?;
    if !rule_is_kernel_nd_accept(rules[1]) {
        return None;
    }
    let excepted =
        rule_skuid_set_with_verdict(rules[2], "!=", "accept", NET_RULE_COMMENT_OTHERS, overflow)?;
    // INVARIANT: the two sets must be EQUAL. If rule 3 excepted a wider set than
    // rule 1 denied, a uid in the difference would be accepted by rule 3 having
    // never been dropped, which is the fail-open the ordering exists to prevent;
    // a narrower rule 3 would deny an operator the net promised to spare.
    if denied == excepted {
        Some(denied)
    } else {
        None
    }
}

/// One uid from a bare-scalar JSON value (or a `"set"` value that itself
/// collapsed to a bare scalar): `as_u64` refuses a string, a float, a bool
/// and a nested object, so a name form or an unrecognised shape yields `None`
/// rather than a wrong uid.
fn one_skuid_scalar(value: &serde_json::Value) -> Option<u32> {
    u32::try_from(value.as_u64()?).ok()
}

/// The uid members of a `meta skuid <op> <right>` match's `right` value, in
/// nft's listed order and with duplicates intact: the caller validates,
/// sorts, dedups and checks cardinality to its own contract. `None` means
/// `right` is not one of the forms nft renders a skuid set as; a non-numeric
/// member anywhere refuses the WHOLE match rather than silently reading a
/// partial set, matching a shape this daemon's own installer never emits.
///
/// SHARED single source of truth for the safety-net recogniser
/// (`rule_skuid_set_with_verdict`, below) and the live-binding reader
/// (`net_rule_one_uids`): nft collapses a single-member anonymous set to a
/// bare scalar with no `"set"` wrapper at all. The real-kernel witness for
/// this collapse is `integration_linux_runtime_activation.rs:1722-1725`
/// (reading only the set form "returned an empty scope for a live one-uid
/// net on the first privileged run of this suite") and the sibling case in
/// `nft_set_json_forms_are_the_shapes_the_parser_reads`
/// (`tests/integration_gf1_recovery.rs`), not `parse_skuid_value`: that
/// function pins a DIFFERENT rule (the per-agent chain's bare `meta skuid ==
/// <uid>`, written without set syntax at all) and says nothing about whether
/// an anonymous SET of one member collapses. `render_uid_set` always writes
/// explicit `{ .. }` braces, even for one uid, so a live table with exactly
/// one denied or excepted uid is exactly where this collapse is reachable.
/// Reading only the multi-member array form in the recogniser would refuse
/// to recognise this daemon's OWN single-uid net as the safety net at all;
/// reading only the array form in the live-binding reader would drop that
/// already-installed uid from source (c) of `resolve_safety_net_scope`. Both
/// callers must resolve every shape nft may emit for the same one-member
/// match identically, or they silently disagree about the SAME live kernel
/// state.
///
/// The accepted surface is kept equal to the set of OBSERVED nft outputs: a
/// `"set"` key whose own value is itself a bare scalar (rather than a
/// one-element array) is not a shape any witness records nft emitting, and
/// is refused rather than speculatively normalised.
fn skuid_right_members(right: &serde_json::Value) -> Option<Vec<u32>> {
    match right.get("set") {
        Some(members) => members.as_array()?.iter().map(one_skuid_scalar).collect(),
        // No "set" wrapper at all: the fully-flattened singleton form.
        None => Some(vec![one_skuid_scalar(right)?]),
    }
}

/// Parse one `meta skuid <op> { .. } <verdict>` rule and return its set, or
/// `None` when the rule is not exactly that shape with exactly `comment`.
///
/// The returned set is ascending and deduplicated so the caller's equality check
/// does not depend on the order nft listed the members in.
fn rule_skuid_set_with_verdict(
    rule: &serde_json::Value,
    op: &str,
    verdict: &str,
    comment: &str,
    overflow: HostOverflowUid,
) -> Option<Vec<u32>> {
    if rule.get("comment").and_then(|v| v.as_str()) != Some(comment) {
        return None;
    }
    let exprs = rule.get("expr").and_then(|v| v.as_array())?;
    // Exactly one match and one verdict: a third expression is an extra
    // condition that narrows or widens what the rule does.
    if exprs.len() != 2 {
        return None;
    }
    let m = exprs[0].get("match")?;
    if m.get("op").and_then(|v| v.as_str()) != Some(op) {
        return None;
    }
    // `meta skuid` renders as a nested object; nothing else is accepted, so a
    // match on any other key (a mark, an interface) is not this rule.
    let left_key = m.get("left")?.get("meta")?.get("key")?.as_str()?;
    if left_key != "skuid" {
        return None;
    }
    // See `skuid_right_members`'s doc: this is the SAME shape-tolerant read
    // `net_rule_one_uids` uses, so the recogniser and the live-binding reader
    // never disagree about what a live table's rule 1/rule 3 denies.
    let raw_members = skuid_right_members(m.get("right")?)?;
    if raw_members.is_empty() {
        return None;
    }
    let mut uids: Vec<u32> = Vec::with_capacity(raw_members.len());
    for raw_uid in &raw_members {
        // Revalidate through the shared three-refusal function: the closed
        // installer type could not have produced 0, the host overflow uid or the
        // sentinel, so a set carrying one was not armed by this daemon.
        validate_safety_net_uid(*raw_uid, overflow).ok()?;
        uids.push(*raw_uid);
    }
    uids.sort_unstable();
    uids.dedup();
    // A set that listed a uid twice is not the shape the installer emits (it
    // deduplicates before rendering).
    if uids.len() != raw_members.len() {
        return None;
    }
    // The verdict object is a single key with a null value (`{"drop": null}`).
    let v = exprs[1].as_object()?;
    if v.len() != 1 || !v.contains_key(verdict) {
        return None;
    }
    Some(uids)
}

/// Whether `rule` is exactly the kernel neighbour-discovery accept rule.
///
/// FAILURE-MODE NOTE for anyone editing this: in the `inet` family nft compiles
/// `icmpv6 type { .. }` into the payload match PLUS an implicit layer-4 protocol
/// dependency, so the listed rule can carry a leading `meta l4proto`/`nfproto`
/// match that the emitter never wrote. That dependency only NARROWS the rule to
/// ICMPv6 traffic, so it is accepted here; any other extra expression is refused,
/// because a widening condition on an accept rule ahead of nothing is exactly the
/// carve-out an agent could aim for. The exact listed form is pinned by the
/// Linux integration probe (`nft_set_json_forms_are_the_shapes_the_parser_reads`
/// in `tests/integration_gf1_recovery.rs`), which runs where nft exists; this
/// tolerance is what keeps the parser honest about a form a macOS builder cannot
/// observe.
fn rule_is_kernel_nd_accept(rule: &serde_json::Value) -> bool {
    if rule.get("comment").and_then(|v| v.as_str()) != Some(NET_RULE_COMMENT_KERNEL_ND) {
        return false;
    }
    let Some(exprs) = rule.get("expr").and_then(|v| v.as_array()) else {
        return false;
    };
    let mut saw_icmpv6_type_set = false;
    let mut saw_accept = false;
    // At most ONE implicit protocol dependency may be skipped.
    let mut saw_protocol_dependency = false;
    for expr in exprs {
        let Some(obj) = expr.as_object() else {
            return false;
        };
        if obj.len() != 1 {
            return false;
        }
        if let Some(m) = obj.get("match") {
            let Some(left) = m.get("left") else {
                return false;
            };
            // The implicit protocol dependency nft adds for an `inet`-family
            // ICMPv6 match: narrowing only, so accepted.
            if let Some(meta_key) = left
                .get("meta")
                .and_then(|v| v.get("key"))
                .and_then(|v| v.as_str())
            {
                // EXACTLY the implicit dependency the probe records, and at most once.
                // A meta match is only safe to skip when it NARROWS the rule to ICMPv6;
                // accepting any operator, any value or a repeat would let a crafted rule
                // carry an extra condition, or a `!=` that inverts the narrowing, past a
                // check whose whole job is to prove this is the shape the installer emits.
                let narrowing_dependency = matches!(meta_key, "l4proto" | "nfproto")
                    && m.get("op").and_then(|v| v.as_str()) == Some("==")
                    && m.get("right")
                        .and_then(|v| v.as_str())
                        .is_some_and(|proto| matches!(proto, "icmpv6" | "ipv6-icmp"));
                if narrowing_dependency && !saw_protocol_dependency {
                    saw_protocol_dependency = true;
                    continue;
                }
                return false;
            }
            let Some(payload) = left.get("payload") else {
                return false;
            };
            let proto_is_icmpv6 =
                payload.get("protocol").and_then(|v| v.as_str()) == Some("icmpv6");
            let field_is_type = payload.get("field").and_then(|v| v.as_str()) == Some("type");
            if !(proto_is_icmpv6 && field_is_type) || saw_icmpv6_type_set {
                return false;
            }
            if m.get("op").and_then(|v| v.as_str()) != Some("==") {
                return false;
            }
            let Some(members) = m
                .get("right")
                .and_then(|v| v.get("set"))
                .and_then(|v| v.as_array())
            else {
                return false;
            };
            // EXACTLY the three neighbour-discovery types, as a set. An extra
            // type (an MLD report, an echo request) is a channel the confined
            // agent may be able to drive, so the check is equality, never
            // containment.
            let mut listed: Vec<&str> = Vec::with_capacity(members.len());
            for member in members {
                match member.as_str() {
                    Some(name) => listed.push(name),
                    None => return false,
                }
            }
            let mut expected: Vec<&str> = KERNEL_ND_ICMPV6_TYPES.to_vec();
            listed.sort_unstable();
            expected.sort_unstable();
            if listed != expected {
                return false;
            }
            saw_icmpv6_type_set = true;
        } else if obj.contains_key("accept") {
            if saw_accept {
                return false;
            }
            saw_accept = true;
        } else {
            return false;
        }
    }
    saw_icmpv6_type_set && saw_accept
}

/// D3 fix round: an independent check, over the SAME inventory
/// [`is_deny_all_safety_net_json`] parses, that the live table's `comment` key
/// is absent entirely. Both disarm arms (`ReclaimOwned` and
/// `FinalizeInterrupted`) require this alongside a
/// positive recogniser answer before it treats a live table as this daemon's
/// safety net (D1 installs the net with no table comment at all); this
/// function answers only the comment-key question and never touches, narrows,
/// or duplicates the recogniser's own shape logic above, which is unchanged
/// and stays the single source of truth for the net's shape. A malformed
/// inventory or a missing matching table object cannot positively prove
/// absence, so both read as "not confirmed absent" (`false`, fail closed).
/// Gated `any(target_os = "linux", test)`, matching this crate's convention
/// for a Linux-only production surface a cross-platform test suite still
/// needs to name; its own test below is the reachability anchor.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn castle_table_comment_is_absent(json: &str) -> bool {
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(json) else {
        return false;
    };
    let Some(items) = doc.get("nftables").and_then(|v| v.as_array()) else {
        return false;
    };
    for item in items {
        let Some(table) = item.get("table") else {
            continue;
        };
        let ours = table.get("family").and_then(|v| v.as_str()) == Some(CASTLE_FAMILY)
            && table.get("name").and_then(|v| v.as_str()) == Some(castle_table());
        if ours {
            return table.get("comment").is_none();
        }
    }
    false
}

/// Build the atomic nft script that CREATES the owned table + its base output
/// chain using nft's fail-on-exists `create` verbs, stamping `marker` as the
/// table comment. Pure/cross-platform so the "uses `create`, never `add`" and
/// marker-embedding invariants are unit-testable without a kernel. (blocker 1)
///
/// Production-used only on Linux (the acquisition path), but exercised by the
/// cross-platform tests, so gated to `any(target_os = "linux", test)` to avoid a
/// dead-code diagnostic under `clippy -D warnings` on the macOS dev lib build.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn build_create_castle_table_script(marker: &str) -> String {
    let castle_table = castle_table();
    // `create` (not `add`): fails the whole transaction if the table/chain
    // already exists, so a raced or foreign same-named table is refused, never
    // adopted or mutated.
    format!(
        "create table {CASTLE_FAMILY} {castle_table} {{ comment \"{marker}\" ; }}\n\
         create chain {CASTLE_FAMILY} {castle_table} output \
         {{ type filter hook output priority 0 ; policy accept ; }}\n"
    )
}

/// Parse `nft -j list table inet sanctuary-castle` into the EXACT owned identity,
/// or reject the whole document as foreign/incompatible. (blocker 2)
///
/// This is stricter than [`output_chain_shape_is_ours_json`] on purpose: that
/// helper only asks "is a correct base output chain present?" and ignores rule
/// objects and regular (non-base) chains, so it would accept a table carrying
/// injected rules, extra chains, or a same-shape delete/recreate. This parser
/// instead requires the document to contain EXACTLY the pristine L2 slice:
///
/// * exactly one `table` object — family `inet`, name `sanctuary-castle`, with a
///   `comment` marker that begins with [`OWNER_MARKER_PREFIX`];
/// * exactly one base output chain, plus zero or more marker-bound `agent_*`
///   chains created by the typed mutation path;
/// * only marker-bound queue/jump rules in those chains; no other nft object.
///
/// Any deviation returns [`NftablesError::ForeignState`]. On success it returns
/// the captured [`CastleTableOwnership`] (both handles + the marker), which the
/// caller binds so a later `nft -j` that no longer matches this exact tuple —
/// including a same-shape replacement whose handles changed — is refused.
///
/// Pure and cross-platform so the exact-ownership refusal is unit-testable
/// without a live kernel (see the adversarial-JSON tests below).
fn has_exact_keys(value: &serde_json::Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
    })
}

/// Per-agent isolation seal: a fixed-length, domain-separated digest of the
/// EXACT uid the daemon installed for one agent's `meta skuid` match, bound to
/// the fortress and the agent it was installed for. It is embedded in the
/// marker-bound rule COMMENT (`:uid:<seal>`) so verification can reject a rule
/// whose uid expression was rewritten in place while its comment was left
/// intact.
///
/// Why a digest, not the raw uid: the comment budget is already spent on the
/// marker and the agent id (see [`MAX_AGENT_ID_LEN`]), and a raw uid in the
/// comment would prove nothing the expression does not already say. The digest
/// binds the uid to `fortress_id` and `agent_id` as well, so the same uid under a
/// different fortress or a different agent does not verify.
///
/// Why UNKEYED: the pure parser has no key, and the security level is
/// deliberately exactly that of every other rule-shape check. An in-place
/// expression mutation (rewrite only the `meta skuid` value) leaves this comment
/// intact, so the recomputed digest no longer matches and the rule is refused.
/// An actor that reconstructs BOTH expressions AND both comments produces a
/// self-consistent inventory this digest cannot catch — that case is caught only
/// by the trusted MANIFEST uid comparison in `parse_owned_table_inventory`, which
/// is why the seal is documented as a consistency check and never as authority.
///
/// `decimal(uid)` is ASCII decimal with no leading zeros and no sign (Rust's
/// `u32` Display), so one uid has exactly one preimage and two spellings of the
/// same uid cannot produce two seals.
///
/// Pure and cross-platform (used by both the linux emission site and the pure
/// parser, and by the adversarial-JSON tests) so it must not be linux-gated.
/// Deliberately carries NO `cfg`: `parse_owned_table_inventory` is unconditional
/// and calls this, so a `cfg(any(target_os = "linux", test))` gate here compiles
/// everywhere the crate is BUILT ON LINUX or built as a test, and fails to
/// compile on a non-Linux non-test build (`cargo build` / `cargo check --lib` on
/// macOS) with a bare "cannot find function in this scope". Failure mode: the
/// Linux CI job and every `cargo test` are green, and the break appears only in
/// a developer's macOS build or in a cross-language test that shells out to
/// `cargo build`, which is exactly where a gate mismatch is hardest to read.
pub(crate) fn agent_uid_seal(fortress_id: &str, agent_id: &str, agent_uid: u32) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    // Domain separation: this digest is never interchangeable with any other
    // SHA-256 use in the daemon (WAL chaining, manifest hashing).
    hasher.update(b"sanctuary-castle:agent-uid-seal:v1\0");
    // NUL-separated, and neither a fortress id nor an agent id may contain NUL
    // (both are ASCII identifier grammars), so the concatenation is unambiguous:
    // no pair of distinct (fortress, agent, uid) triples shares a preimage.
    hasher.update(fortress_id.as_bytes());
    hasher.update([0u8]);
    hasher.update(agent_id.as_bytes());
    hasher.update([0u8]);
    hasher.update(agent_uid.to_string().as_bytes());
    let digest = hasher.finalize();
    // Truncated to AGENT_UID_SEAL_HEX_LEN / 2 bytes; the hex width is what the
    // comment budget above is derived from, so the two must move together.
    hex::encode(&digest[..AGENT_UID_SEAL_HEX_LEN / 2])
}

/// Parse an nft `meta skuid == <integer>` match expression into its uid.
///
/// INVARIANT: only a BARE INTEGER is accepted. nft renders `meta skuid` through
/// a uid symbol table, so an account name could appear where the daemon wrote a
/// number; a parser that accepted names would have to resolve them against
/// `/etc/passwd` at verification time, making the kernel binding's meaning depend
/// on a mutable file. Refusing a name is fail-closed (the binding reads foreign
/// and deny-all re-arms) and the daemon always emits numerically. The listing
/// form is probed per nftables version before this shape is trusted.
///
/// uid 0 is refused here as well as at emission: root is never a confined agent,
/// and a `skuid 0` rule in an owned table is a widening, not a binding.
fn parse_skuid_value(expr: &serde_json::Value) -> Option<u32> {
    if !has_exact_keys(expr, &["match"]) {
        return None;
    }
    let matched = expr.get("match")?;
    if !has_exact_keys(matched, &["op", "left", "right"])
        || !has_exact_keys(matched.get("left")?, &["meta"])
        || !has_exact_keys(matched.get("left")?.get("meta")?, &["key"])
    {
        return None;
    }
    if matched.get("op")?.as_str()? != "==" {
        return None;
    }
    if matched.get("left")?.get("meta")?.get("key")?.as_str()? != "skuid" {
        return None;
    }
    // `as_u64` refuses a string, a float, a bool and a nested object, so a name
    // form or a structured range is rejected before the range check below.
    let uid = u32::try_from(matched.get("right")?.as_u64()?).ok()?;
    if uid < 1 {
        return None;
    }
    Some(uid)
}

fn parse_mark_assignment(expr: &serde_json::Value) -> Option<u32> {
    if !has_exact_keys(expr, &["mangle"]) {
        return None;
    }
    let mangle = expr.get("mangle")?;
    if !has_exact_keys(mangle, &["key", "value"])
        || !has_exact_keys(mangle.get("key")?, &["meta"])
        || !has_exact_keys(mangle.get("key")?.get("meta")?, &["key"])
    {
        return None;
    }
    if mangle.get("key")?.get("meta")?.get("key")?.as_str()? != "mark" {
        return None;
    }
    u32::try_from(mangle.get("value")?.as_u64()?).ok()
}

/// Validate one owned per-agent chain body and return the uid it binds, or
/// `None` for the fail-closed unconditional-drop body, which binds no uid.
fn validate_owned_body_expr(
    expr: &serde_json::Value,
    agent_id: &str,
    fail_closed: bool,
) -> Result<Option<u32>, NftablesError> {
    let terms = expr.as_array().ok_or_else(|| {
        NftablesError::ForeignState("owned agent body has no expression array".to_string())
    })?;
    if fail_closed {
        if terms.len() == 1
            && has_exact_keys(&terms[0], &["drop"])
            && terms[0].get("drop").is_some_and(serde_json::Value::is_null)
        {
            return Ok(None);
        }
        return Err(NftablesError::ForeignState(
            "fail-closed agent body is not one unconditional drop".to_string(),
        ));
    }
    if terms.len() != 3 {
        return Err(NftablesError::ForeignState(
            "queued agent body is not the exact skuid/mark/queue expression".to_string(),
        ));
    }
    let binding = parse_skuid_value(&terms[0]).ok_or_else(|| {
        NftablesError::ForeignState("queued agent body has no typed skuid match".to_string())
    })?;
    if parse_mark_assignment(&terms[1]) != Some(crate::nfqueue::agent_mark(agent_id)) {
        return Err(NftablesError::ForeignState(
            "queued agent body does not set the derived attribution mark".to_string(),
        ));
    }
    if !has_exact_keys(&terms[2], &["queue"])
        || !has_exact_keys(
            terms[2].get("queue").unwrap_or(&serde_json::Value::Null),
            &["num"],
        )
        || terms[2]
            .get("queue")
            .and_then(|queue| queue.get("num"))
            .and_then(|num| num.as_u64())
            != Some(0)
    {
        return Err(NftablesError::ForeignState(
            "queued agent body does not terminate at NFQUEUE 0".to_string(),
        ));
    }
    Ok(Some(binding))
}

/// Validate the base-output jump for one agent and return the uid it routes.
fn validate_owned_jump_expr(
    expr: &serde_json::Value,
    expected_chain: &str,
) -> Result<u32, NftablesError> {
    let terms = expr.as_array().ok_or_else(|| {
        NftablesError::ForeignState("owned output jump has no expression array".to_string())
    })?;
    if terms.len() != 2 {
        return Err(NftablesError::ForeignState(
            "owned output jump is not the exact skuid/goto expression".to_string(),
        ));
    }
    let binding = parse_skuid_value(&terms[0]).ok_or_else(|| {
        NftablesError::ForeignState("owned output jump has no typed skuid match".to_string())
    })?;
    // Must match `build_agent_jump_rule` and `parse_jump_rule_handles`: the base
    // output rule routes the agent cgroup with a `goto` (a TERMINATING verdict,
    // so control never returns to the accept-policy base chain), which nft JSON
    // keys as `"goto"`, NOT `"jump"`. Checking `"jump"` here rejected the
    // daemon's OWN base-output rule, so every capture/verify of an owned table
    // already carrying a wired agent goto failed as "wrong agent chain" (the
    // second agent load, and production reclaim/verify once an agent is wired).
    // The verb this validator accepts MUST equal the verb the builder emits;
    // `parse_jump_rule_handles` documents the same "only goto" contract.
    if !has_exact_keys(&terms[1], &["goto"])
        || !has_exact_keys(
            terms[1].get("goto").unwrap_or(&serde_json::Value::Null),
            &["target"],
        )
        || terms[1]
            .get("goto")
            .and_then(|goto| goto.get("target"))
            .and_then(|target| target.as_str())
            != Some(expected_chain)
    {
        return Err(NftablesError::ForeignState(
            "owned output jump targets the wrong agent chain".to_string(),
        ));
    }
    Ok(binding)
}

struct ParsedOwnedTableInventory {
    ownership: CastleTableOwnership,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    agent_ids: Vec<String>,
    /// Every `agent_id -> uid` binding the owned shape declared, collected BEFORE
    /// the trusted manifest comparison. This is source (c) of the safety net's
    /// deny set.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    uid_bindings: std::collections::HashMap<String, u32>,
}

/// The TWO-PHASE result of parsing an owned-table inventory.
///
/// PHASE ONE is everything the kernel dump can prove about itself plus the
/// ownership marker: shape, marker, handles, seal recomputation, body/jump
/// agreement and cardinality. PHASE TWO is the single check whose input did NOT
/// come from the dump: comparing the live uid against the uid the current signed
/// manifest confines.
///
/// The two are separated because the safety net needs the uid bindings of a table
/// that IS this daemon's own owned table but whose binding has drifted off the
/// current manifest. Such a table is exactly the drift case the net exists for: a
/// rotated-away uid may still have live processes, so its uid must enter the DENY
/// set. Collapsing the two phases into one `Err` discarded those bindings and
/// narrowed the net.
///
/// INVARIANT: a `Bindings` value is only ever produced after PHASE ONE has passed
/// IN FULL. A structurally foreign table, a marker or handle mismatch, a malformed
/// pairing or a seal failure is an `Err` and yields NOTHING, and a failure that
/// lands after some bindings were already collected (a valid binding followed by a
/// foreign rule) is also an `Err`, so no partial set escapes. Must match the
/// late-failure test `owned_inventory_exposes_no_partial_binding_set_on_a_late_failure`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
enum OwnedInventoryPhases {
    /// Both phases passed.
    Verified(ParsedOwnedTableInventory),
    /// Phase one passed IN FULL; phase two (the trusted uid comparison) failed.
    /// The bindings are trustworthy as "what this owned table routes", which is
    /// all source (c) claims, and `detail` is the refusal a caller that needs
    /// phase two must still surface.
    UidMismatch {
        inventory: ParsedOwnedTableInventory,
        detail: String,
    },
}

/// Parse an owned-table inventory and check it against `expectation`.
///
/// `expectation` is the whole security content of the agent-binding half of this
/// parse: shape, seal, body/jump agreement and cardinality all prove the
/// inventory is INTERNALLY consistent, which an actor that rewrote both
/// expressions and both comments can also achieve. Only
/// [`ExpectedAgentBinding::Confined`] compares the live uid against a value this
/// process did not read out of the kernel.
fn parse_owned_table_inventory_phases(
    json: &str,
    expectation: &ExpectedAgentBinding,
) -> Result<OwnedInventoryPhases, NftablesError> {
    let doc: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| NftablesError::ForeignState(format!("nft -j output did not parse: {e}")))?;
    let items = doc
        .get("nftables")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            NftablesError::ForeignState("nft -j output has no `nftables` array".to_string())
        })?;

    let mut table_handle: Option<u64> = None;
    let mut marker: Option<String> = None;
    let mut base_chain_handle: Option<u64> = None;
    let mut agent_chains = std::collections::HashMap::<String, String>::new();
    let mut owned_rules: Vec<(String, String, serde_json::Value)> = Vec::new();

    // Resolve the authenticated acquisition marker first; nft JSON ordering is
    // not a contract and later chain/rule validation depends on it.
    let table_values: Vec<&serde_json::Value> =
        items.iter().filter_map(|item| item.get("table")).collect();
    if table_values.len() != 1 {
        return Err(NftablesError::ForeignState(
            "expected exactly one owned table object".to_string(),
        ));
    }
    let expected_marker = table_values[0]
        .get("comment")
        .and_then(|value| value.as_str())
        .filter(|value| value.starts_with(OWNER_MARKER_PREFIX))
        .ok_or_else(|| {
            NftablesError::ForeignState("owned table has no valid ownership marker".to_string())
        })?
        .to_string();

    for item in items {
        let obj = item.as_object().ok_or_else(|| {
            NftablesError::ForeignState("nft -j item was not an object".to_string())
        })?;
        // Each nft -j item is a single-key object keyed by its kind.
        if obj.len() != 1 {
            return Err(NftablesError::ForeignState(
                "nft -j inventory item must contain exactly one object kind".to_string(),
            ));
        }
        for (kind, val) in obj {
            match kind.as_str() {
                // Ruleset metadata: not part of the owned shape.
                "metainfo" => {}
                "table" => {
                    if table_handle.is_some() {
                        return Err(NftablesError::ForeignState(
                            "more than one table object present".to_string(),
                        ));
                    }
                    let ours = val.get("family").and_then(|v| v.as_str()) == Some(CASTLE_FAMILY)
                        && val.get("name").and_then(|v| v.as_str()) == Some(castle_table());
                    if !ours {
                        return Err(NftablesError::ForeignState(
                            "a table object is not inet/sanctuary-castle".to_string(),
                        ));
                    }
                    let handle = val.get("handle").and_then(|v| v.as_u64()).ok_or_else(|| {
                        NftablesError::ForeignState("owned table has no handle".to_string())
                    })?;
                    // The marker is the ownership proof: a foreign same-named
                    // table cannot carry our random nonce, and its absence means
                    // "not created by this acquisition path."
                    let comment = val.get("comment").and_then(|v| v.as_str()).ok_or_else(|| {
                        NftablesError::ForeignState(
                            "sanctuary-castle table carries no ownership marker comment"
                                .to_string(),
                        )
                    })?;
                    if !comment.starts_with(OWNER_MARKER_PREFIX) {
                        return Err(NftablesError::ForeignState(
                            "table comment is not a sanctuary ownership marker".to_string(),
                        ));
                    }
                    table_handle = Some(handle);
                    marker = Some(comment.to_string());
                }
                "chain" => {
                    let name = val.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    if name.starts_with(AGENT_CHAIN_PREFIX) {
                        let comment = val.get("comment").and_then(|v| v.as_str()).unwrap_or("");
                        let agent_id = comment
                            .strip_prefix(&format!("{}:agent:", expected_marker))
                            .filter(|id| !id.is_empty())
                            .unwrap_or("");
                        // Must match `validate_agent_binding_input`: an agent id
                        // longer than the sealed-comment budget could never have
                        // been installed by this daemon, so one in a live table is
                        // foreign.
                        let agent_id_is_typed = agent_id.len() <= MAX_AGENT_ID_LEN
                            && agent_id.bytes().all(|byte| {
                                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
                            });
                        let is_agent_chain = val.get("family").and_then(|v| v.as_str())
                            == Some(CASTLE_FAMILY)
                            && val.get("table").and_then(|v| v.as_str()) == Some(castle_table())
                            && agent_chain_name(agent_id) == name
                            && agent_id_is_typed
                            && val.get("hook").is_none()
                            && val.get("policy").is_none();
                        if !is_agent_chain
                            || agent_chains
                                .insert(name.to_string(), agent_id.to_string())
                                .is_some()
                        {
                            return Err(NftablesError::ForeignState(
                                "invalid or duplicate marker-bound agent chain".to_string(),
                            ));
                        }
                        continue;
                    }
                    if base_chain_handle.is_some() {
                        return Err(NftablesError::ForeignState(
                            "more than one base output chain present".to_string(),
                        ));
                    }
                    // Must be EXACTLY our base output chain. A regular (non-base,
                    // hookless) chain, a wrong hook/prio/policy, or a split
                    // family/table all fail here.
                    let is_ours = val.get("family").and_then(|v| v.as_str()) == Some(CASTLE_FAMILY)
                        && val.get("table").and_then(|v| v.as_str()) == Some(castle_table())
                        && val.get("name").and_then(|v| v.as_str()) == Some("output")
                        && val.get("type").and_then(|v| v.as_str()) == Some("filter")
                        && val.get("hook").and_then(|v| v.as_str()) == Some("output")
                        && val.get("prio").and_then(|v| v.as_i64()) == Some(0)
                        && val.get("policy").and_then(|v| v.as_str()) == Some("accept");
                    if !is_ours {
                        return Err(NftablesError::ForeignState(
                            "the sole chain is not this daemon's exact base output chain"
                                .to_string(),
                        ));
                    }
                    let handle = val.get("handle").and_then(|v| v.as_u64()).ok_or_else(|| {
                        NftablesError::ForeignState("owned base chain has no handle".to_string())
                    })?;
                    base_chain_handle = Some(handle);
                }
                "rule" => {
                    let family_ok =
                        val.get("family").and_then(|v| v.as_str()) == Some(CASTLE_FAMILY);
                    let table_ok =
                        val.get("table").and_then(|v| v.as_str()) == Some(castle_table());
                    let chain = val.get("chain").and_then(|v| v.as_str()).unwrap_or("");
                    let comment = val.get("comment").and_then(|v| v.as_str()).unwrap_or("");
                    let marker_bound = comment.starts_with(&format!("{}:", expected_marker));
                    let known_chain = chain == "output" || chain.starts_with(AGENT_CHAIN_PREFIX);
                    if !family_ok || !table_ok || !marker_bound || !known_chain {
                        return Err(NftablesError::ForeignState(
                            "unowned or malformed rule in owned table inventory".to_string(),
                        ));
                    }
                    owned_rules.push((
                        chain.to_string(),
                        comment.to_string(),
                        val.get("expr").cloned().unwrap_or(serde_json::Value::Null),
                    ));
                }
                // ANY other object kind (rule, set, map, flowtable, element, …)
                // is foreign to the owned L2 inventory. Table, chain, and rule
                // are handled above; sets/maps/flowtables/elements are never an
                // implicit extension of the authenticated ownership claim.
                other => {
                    return Err(NftablesError::ForeignState(format!(
                        "unexpected nft object `{other}` in sanctuary-castle table \
                         (expected only the marker-bound table/chains/rules inventory)"
                    )));
                }
            }
        }
    }

    let table_handle = table_handle.ok_or_else(|| {
        NftablesError::ForeignState("no owned sanctuary-castle table object present".to_string())
    })?;
    let marker = marker.ok_or_else(|| {
        NftablesError::ForeignState("owned table has no ownership marker".to_string())
    })?;
    let base_chain_handle = base_chain_handle.ok_or_else(|| {
        NftablesError::ForeignState("no owned base output chain present".to_string())
    })?;
    let mut body_counts = std::collections::HashMap::<String, usize>::new();
    let mut jump_counts = std::collections::HashMap::<String, usize>::new();
    let mut uid_bindings = std::collections::HashMap::<String, u32>::new();
    // The deferred PHASE TWO refusal. Only the FIRST mismatch is kept: the detail
    // names the earliest drifted binding, and a later one adds nothing a caller
    // acts on.
    let mut pending_uid_mismatch: Option<String> = None;
    for (chain, comment, expr) in owned_rules {
        let is_jump = chain == "output";
        let fail_closed = !is_jump && comment.contains(":failclosed:");
        // Strip the marker-bound role prefix. The remainder is `{agent_id}` for a
        // fail-closed unconditional-drop body (no uid match to seal) or
        // `{agent_id}:uid:{seal}` for any rule carrying a `meta skuid` match
        // (the base-output jump, and the queued per-agent body).
        let remainder = if is_jump {
            comment.strip_prefix(&format!("{}:jump:", expected_marker))
        } else {
            comment
                .strip_prefix(&format!("{}:queue:", expected_marker))
                .or_else(|| comment.strip_prefix(&format!("{}:failclosed:", expected_marker)))
        }
        .filter(|rest| !rest.is_empty())
        .ok_or_else(|| {
            NftablesError::ForeignState("owned rule comment has wrong role binding".to_string())
        })?;
        // Separate the agent id from the authenticated uid seal. Agent ids are
        // the typed identifier grammar (ASCII alphanumeric / `-` / `_`, no `:`),
        // so the FIRST `AGENT_UID_SEAL_INFIX` is always the seal delimiter and
        // everything before it is the agent id. Must match the comment the
        // emitter writes in `replace_agent_chain_and_jump_impl`.
        let (agent_id, declared_seal) = match remainder.split_once(AGENT_UID_SEAL_INFIX) {
            Some((id, seal)) => (id, Some(seal)),
            None => (remainder, None),
        };
        if agent_id.is_empty() {
            return Err(NftablesError::ForeignState(
                "owned rule comment has an empty agent id".to_string(),
            ));
        }
        let expected_chain = agent_chain_name(agent_id);
        if agent_chains.get(&expected_chain).map(String::as_str) != Some(agent_id)
            || (chain != "output" && chain != expected_chain)
        {
            return Err(NftablesError::ForeignState(
                "owned rule does not bind to its declared agent chain".to_string(),
            ));
        }
        let binding = if is_jump {
            Some(validate_owned_jump_expr(&expr, &expected_chain)?)
        } else {
            validate_owned_body_expr(&expr, agent_id, fail_closed)?
        };
        // Per-agent isolation invariant, in two layers that must not be
        // confused. The body/jump agreement below proves the two rules match
        // EACH OTHER, and the seal proves neither expression was rewritten
        // without its comment; NEITHER proves the pair matches the uid the
        // OPERATOR signed. An actor holding CAP_NET_ADMIN can rewrite both
        // expressions AND recompute both unkeyed seals, producing a fully
        // self-consistent inventory that routes some OTHER uid into the agent's
        // chain while the real agent's traffic misses the goto and reaches
        // `policy accept`. Only the manifest comparison below refuses that, and
        // only where the caller supplied a trusted expectation.
        if let Some(expr_uid) = binding {
            let declared_seal = declared_seal.ok_or_else(|| {
                NftablesError::ForeignState(
                    "a skuid-matching owned rule carries no authenticated agent-uid seal"
                        .to_string(),
                )
            })?;
            // The seal's fortress id is the caller's, never one read out of the
            // dump: a seal recomputed under a fortress id the kernel state itself
            // supplied would verify against whatever an attacker wrote.
            match expectation.seal_fortress_id() {
                Some(seal_fortress_id) => {
                    if agent_uid_seal(seal_fortress_id, agent_id, expr_uid) != declared_seal {
                        return Err(NftablesError::ForeignState(format!(
                            "agent {agent_id:?} skuid match {expr_uid} does not match its \
                             authenticated agent-uid seal; an in-place uid rewrite, a \
                             wrong-agent or a wrong-fortress binding is not the owned \
                             per-agent binding"
                        )));
                    }
                }
                None if expectation.tolerates_unverifiable_seal() => {}
                None => {
                    return Err(NftablesError::ForeignState(format!(
                        "agent {agent_id:?} carries a live per-agent uid binding while the \
                         current policy confines no agent uid; an unverifiable binding is \
                         refused fail-closed rather than adopted as owned"
                    )));
                }
            }
            // The TRUSTED expectation. This is the only check here whose input
            // did not come from the kernel dump, so it is the only one a
            // self-consistent forgery cannot satisfy.
            if let ExpectedAgentBinding::Confined { agent_uid, .. } = expectation {
                if expr_uid != *agent_uid && pending_uid_mismatch.is_none() {
                    // PHASE TWO failure, DEFERRED rather than returned here. The
                    // rest of phase one (cardinality, body/jump agreement, the
                    // remaining rules) must still run, because a `Bindings` result
                    // is only honest if the WHOLE owned shape passed. Every caller
                    // that needs phase two still refuses; the safety net is the one
                    // consumer that needs the bindings of a drifted-but-ours table,
                    // since a rotated-away uid may still have live processes.
                    pending_uid_mismatch = Some(format!(
                        "agent {agent_id:?} skuid match {expr_uid} is not the uid the current \
                         signed manifest confines ({agent_uid}); a live binding that routes \
                         a different uid is refused fail-closed"
                    ));
                }
            }
        } else if declared_seal.is_some() {
            // A non-skuid-matching body (the fail-closed unconditional drop) must
            // NOT carry a uid seal: a seal there is a malformed/foreign comment.
            return Err(NftablesError::ForeignState(
                "a fail-closed owned rule must not carry an agent-uid seal".to_string(),
            ));
        }
        if let Some(binding) = binding {
            if let Some(prior) = uid_bindings.insert(agent_id.to_string(), binding) {
                if prior != binding {
                    return Err(NftablesError::ForeignState(
                        "owned body and output jump disagree on the agent uid binding".to_string(),
                    ));
                }
            }
        }
        let counts = if is_jump {
            &mut jump_counts
        } else {
            &mut body_counts
        };
        *counts.entry(agent_id.to_string()).or_default() += 1;
    }
    // The marker is an authenticated inventory root: every declared agent
    // chain must have exactly one marker-bound body rule and exactly one
    // marker-bound output jump, and there may be no orphan rule. This makes a
    // complete legitimate multi-agent table reclaimable after restart while
    // refusing partial/crashed or foreign compositions.
    for agent_id in agent_chains.values() {
        if body_counts.get(agent_id) != Some(&1) || jump_counts.get(agent_id) != Some(&1) {
            return Err(NftablesError::ForeignState(format!(
                "agent {agent_id:?} does not have exactly one owned body rule and one owned jump"
            )));
        }
    }
    let mut agent_ids: Vec<String> = agent_chains.into_values().collect();
    agent_ids.sort_unstable();
    let inventory = ParsedOwnedTableInventory {
        ownership: CastleTableOwnership {
            table_handle,
            base_chain_handle,
            marker,
        },
        agent_ids,
        uid_bindings,
    };
    // Phase one has now passed IN FULL (every rule read, every pairing and count
    // checked), so a deferred phase-two failure may safely expose the bindings.
    match pending_uid_mismatch {
        None => Ok(OwnedInventoryPhases::Verified(inventory)),
        Some(detail) => Ok(OwnedInventoryPhases::UidMismatch { inventory, detail }),
    }
}

/// The agent-id prefix the daemon derives from a manifest-admitted uid.
///
/// The derivation has to be a FUNCTION and not a `format!` at each site because
/// three separate places must agree on it byte-for-byte: the acquisition that
/// installs the binding, the readback that proves it, and the set rule that
/// health re-applies on every poll. It is also a seal input through
/// [`AgentRulesetId::agent_id`], so a drift here would make a legitimate rule
/// fail to verify after a restart. Must match the protection subject
/// `<fortress>/uid-<U>` the WAL attributes denials to.
pub const CONFINED_AGENT_ID_PREFIX: &str = "uid-";

/// The agent id for a manifest-admitted uid. See [`CONFINED_AGENT_ID_PREFIX`].
///
/// Public because the privileged integration suite has to name the SAME chain
/// the daemon installs: a test that spelled the id itself would be a
/// hand-mirrored copy of this derivation, and the first change here would leave
/// it silently installing a second chain for the same uid.
#[cfg(any(target_os = "linux", test))]
pub fn confined_agent_id(agent_uid: u32) -> String {
    format!("{CONFINED_AGENT_ID_PREFIX}{agent_uid}")
}

/// Every live `(agent_id, uid)` binding an owned table declares: the set the
/// slice-A rule is stated over.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OwnedBindingInventory {
    /// Ascending by agent id, so a comparison against the expected singleton is
    /// an equality and not a search.
    pub(crate) bindings: Vec<(String, u32)>,
}

/// The owned table's binding set, with the slice-A set rule applied.
///
/// This MIRRORS `OwnedInventoryPhases` (same two variants, inventory in both)
/// rather than re-exporting it: the phases enum is the frozen parser's own
/// result and phase two there is the uid comparison alone, whereas the verdict
/// here also carries the cardinality and agent-id half of the set rule. Both
/// outcomes carry the inventory because the safety net's deny set needs the uids
/// of a table that IS ours but whose binding set is wrong.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OwnedBindingSet {
    /// The live set is exactly what the armed identity requires.
    Verified(OwnedBindingInventory),
    /// The owned shape passed in full, but the live set is not the one the armed
    /// identity requires. `detail` is the refusal a caller must surface.
    UidMismatch {
        inventory: OwnedBindingInventory,
        detail: String,
    },
}

#[cfg(any(target_os = "linux", test))]
impl OwnedBindingSet {
    /// The inventory, whichever outcome this is.
    pub(crate) fn inventory(&self) -> &OwnedBindingInventory {
        match self {
            Self::Verified(inventory) | Self::UidMismatch { inventory, .. } => inventory,
        }
    }
}

/// THE SET RULE, over an already-parsed owned inventory. Pure over the JSON so
/// every arm is unit-testable without a kernel.
///
/// INVARIANT this states, and why a uid comparison alone does not: the frozen
/// parser compares the uid of each live binding and never the agent id or the
/// cardinality, so a SECOND chain bound to the same uid under another agent id
/// reads as `Verified` there. Such a chain would take the uid's packets on rule
/// order, and its WAL rows would attribute to the wrong protection subject. The
/// live set must therefore be exactly `{(uid-<U>, U)}` under `Confined { U }`,
/// and exactly empty under any expectation that confines nobody.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn owned_table_binding_set_from_json(
    json: &str,
    ownership: &CastleTableOwnership,
    expectation: &ExpectedAgentBinding,
) -> Result<OwnedBindingSet, NftablesError> {
    let (parsed, phase_two_detail) = match parse_owned_table_inventory_phases(json, expectation)? {
        OwnedInventoryPhases::Verified(parsed) => (parsed, None),
        OwnedInventoryPhases::UidMismatch { inventory, detail } => (inventory, Some(detail)),
    };
    if &parsed.ownership != ownership {
        return Err(NftablesError::ForeignState(format!(
            "sanctuary-castle table identity changed since acquisition \
             (expected handles table={}/chain={} marker={}, found table={}/chain={} marker={}); \
             a same-name replacement or mutation is not the owned object",
            ownership.table_handle,
            ownership.base_chain_handle,
            ownership.marker,
            parsed.ownership.table_handle,
            parsed.ownership.base_chain_handle,
            parsed.ownership.marker,
        )));
    }
    let mut bindings: Vec<(String, u32)> = parsed
        .uid_bindings
        .iter()
        .map(|(agent_id, uid)| (agent_id.clone(), *uid))
        .collect();
    bindings.sort_unstable();
    let inventory = OwnedBindingInventory { bindings };
    // A phase-two uid failure is already a set failure; keep the parser's wording
    // so the two layers do not describe the same drift differently.
    if let Some(detail) = phase_two_detail {
        return Ok(OwnedBindingSet::UidMismatch { inventory, detail });
    }
    let expected: Vec<(String, u32)> = match expectation {
        ExpectedAgentBinding::Confined { agent_uid, .. } => {
            vec![(confined_agent_id(*agent_uid), *agent_uid)]
        }
        // Every other expectation means "no trusted confined uid to bind here",
        // and the empty expected set is what makes that explicit rather than
        // implied. The three are listed rather than folded into a wildcard so a
        // NEW expectation variant has to state its own set-rule answer instead of
        // silently inheriting "expect nothing", which would read a live binding
        // as legitimate.
        ExpectedAgentBinding::NoneConfined
        | ExpectedAgentBinding::SealOnly { .. }
        | ExpectedAgentBinding::StructureOnly => Vec::new(),
    };
    if inventory.bindings == expected {
        return Ok(OwnedBindingSet::Verified(inventory));
    }
    let detail = format!(
        "the live per-agent binding set is {:?}, not the {:?} the armed identity requires; a \
         second chain for the same uid, a chain under another agent id, or a missing binding \
         is refused fail-closed",
        inventory.bindings, expected
    );
    Ok(OwnedBindingSet::UidMismatch { inventory, detail })
}

/// [`owned_table_binding_set_from_json`] against the LIVE table.
#[cfg(target_os = "linux")]
pub(crate) fn owned_table_binding_set(
    ownership: &CastleTableOwnership,
    expectation: &ExpectedAgentBinding,
) -> Result<OwnedBindingSet, NftablesError> {
    let json = linux::list_owned_castle_table_json_for_binding_set()?;
    owned_table_binding_set_from_json(&json, ownership, expectation)
}

/// The health-path reading of [`owned_table_binding_set`]: anything but the
/// exact required set is a PROVEN loss of the owned wall.
///
/// INVARIANT at this line: health must require the BINDING, not merely the
/// table. A table whose agent chain was deleted still verifies as the owned
/// object under the ownership checks alone, and readiness would survive the
/// removal of the only rule that confines the agent. Mapping a wrong set to
/// `ForeignState` is what makes `classify_nft_ownership_probe` read it as a
/// proven loss and re-arm the net that names the uid.
#[cfg(target_os = "linux")]
pub(crate) fn verify_owned_castle_table_binding(
    ownership: &CastleTableOwnership,
    expectation: &ExpectedAgentBinding,
) -> Result<(), NftablesError> {
    match owned_table_binding_set(ownership, expectation)? {
        OwnedBindingSet::Verified(_) => Ok(()),
        OwnedBindingSet::UidMismatch { detail, .. } => Err(NftablesError::ForeignState(detail)),
    }
}

/// Pure parser used by health and ownership checks. Parsing untrusted inventory
/// must never mutate the process-global packet-attribution registry.
pub fn parse_owned_table_identity(
    json: &str,
    expectation: &ExpectedAgentBinding,
) -> Result<CastleTableOwnership, NftablesError> {
    // POLARITY UNCHANGED for every existing caller: a phase-two uid mismatch is
    // still a refusal here, with the same message. Only the safety-net resolver
    // reads the two phases apart, through `parse_owned_table_inventory_phases`.
    match parse_owned_table_inventory_phases(json, expectation)? {
        OwnedInventoryPhases::Verified(parsed) => Ok(parsed.ownership),
        OwnedInventoryPhases::UidMismatch { detail, .. } => {
            Err(NftablesError::ForeignState(detail))
        }
    }
}

/// List the live `sanctuary-castle` table as `nft -j` JSON, or `None` when no such
/// table exists.
///
/// Absence is `Ok(None)`, not an error: "there is no table" and "the table could
/// not be read" resolve the safety net's source (c) differently, so they must not
/// arrive as the same value.
#[cfg(target_os = "linux")]
pub fn list_castle_table_json() -> Result<Option<String>, NftablesError> {
    linux::list_castle_table_json_impl()
}

#[cfg(not(target_os = "linux"))]
pub fn list_castle_table_json() -> Result<Option<String>, NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Source (c) of the safety net's deny set: the `meta skuid` bindings the LIVE
/// owned table declares.
///
/// INVARIANT on the three arms, and why each is distinct: `Bindings` comes only
/// from a table whose whole owned shape passed, so the uids are what this
/// daemon's own table routes. `NotOurTable` is a structurally foreign or
/// ownership-mismatched table, which yields NOTHING; an identity-parser error is
/// NEVER read as "the table has no bindings", because those two would resolve the
/// net to different scopes. `Unreadable` keeps the reason so the audit row's
/// `sources` field can say the live table was not consulted rather than implying
/// it was empty.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveTableBindings {
    /// The owned shape passed; these are its declared uids, ascending.
    Bindings(Vec<u32>),
    /// The live table is not this daemon's owned table. No uids.
    NotOurTable { detail: String },
    /// The live table could not be read at all. No uids, and the reason is kept.
    Unreadable { detail: String },
}

/// Read source (c) from an owned-table listing.
///
/// Pure over the JSON so every arm is unit-testable without a kernel.
#[cfg(any(target_os = "linux", test))]
pub fn live_table_uid_bindings(
    json: &str,
    expectation: &ExpectedAgentBinding,
    overflow: HostOverflowUid,
) -> LiveTableBindings {
    // FIRST: the live table may be this daemon's OWN net rather than an owned wall.
    // The net carries no owner marker and `policy drop`, so the owned-table parser
    // reads it as foreign; treating that as "no bindings" would drop the uids the net
    // itself already denies, and a restart could then install a NARROWER net than the
    // one currently in the kernel. When the live table is our net, source (c) IS rule
    // 1's set, and it is empty for the zero-rule host-wide shape.
    // Must match `is_deny_all_safety_net_json`, whose shape this reads.
    if is_deny_all_safety_net_json(json, overflow) {
        return LiveTableBindings::Bindings(net_rule_one_uids(json));
    }
    match parse_owned_table_inventory_phases(json, expectation) {
        Ok(OwnedInventoryPhases::Verified(parsed)) => {
            LiveTableBindings::Bindings(sorted_bindings(&parsed))
        }
        // A table that IS ours but whose binding drifted off the current manifest
        // is exactly the case the net exists for: the drifted uid may still have
        // live processes, so it must be DENIED even though the binding is refused.
        Ok(OwnedInventoryPhases::UidMismatch { inventory, .. }) => {
            LiveTableBindings::Bindings(sorted_bindings(&inventory))
        }
        Err(err) => LiveTableBindings::NotOurTable {
            detail: err.to_string(),
        },
    }
}

/// Rule 1's uid set from a listing already recognised as this daemon's net.
///
/// Empty for the v1 host-wide shape, which carries no rules at all. Only called
/// after `is_deny_all_safety_net_json` has accepted the listing, so the shape is
/// already proven and a missing field here means the net has no identity rule.
#[cfg(any(target_os = "linux", test))]
fn net_rule_one_uids(json: &str) -> Vec<u32> {
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let Some(items) = doc.get("nftables").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    for item in items {
        let Some(rule) = item.get("rule") else {
            continue;
        };
        if rule.get("comment").and_then(|v| v.as_str()) != Some(NET_RULE_COMMENT_IDENTITY) {
            continue;
        }
        let Some(right) = rule
            .get("expr")
            .and_then(|v| v.as_array())
            .and_then(|exprs| exprs.first())
            .and_then(|e| e.get("match"))
            .and_then(|m| m.get("right"))
        else {
            return Vec::new();
        };
        // SHARED with the safety-net recogniser's `rule_skuid_set_with_verdict`:
        // see `skuid_right_members`'s doc for why every shape nft may emit for a
        // one-member `meta skuid { .. }` match must resolve to the same uid, or
        // this reader and the recogniser silently disagree about the SAME live
        // kernel state.
        let mut uids = match skuid_right_members(right) {
            Some(members) => members,
            None => return Vec::new(),
        };
        uids.sort_unstable();
        uids.dedup();
        return uids;
    }
    Vec::new()
}

#[cfg(any(target_os = "linux", test))]
fn sorted_bindings(parsed: &ParsedOwnedTableInventory) -> Vec<u32> {
    let mut uids: Vec<u32> = parsed.uid_bindings.values().copied().collect();
    uids.sort_unstable();
    uids.dedup();
    uids
}

// ---- Public API (platform-dispatching) ------------------------------------

/// Install the dedicated `sanctuary-castle` table if absent.
/// Per scope-lock section 7 E7.2: namespace separation from the operator's
/// existing firewall (ufw, firewalld, etc.).
#[cfg(target_os = "linux")]
pub fn install_castle_table() -> Result<(), NftablesError> {
    if castle_table() == CASTLE_TABLE {
        return Err(NftablesError::InvocationFailed(
            "unowned production table installation is disabled; use the authenticated ownership acquisition path"
                .to_string(),
        ));
    }
    linux::install_castle_table_impl()
}

#[cfg(not(target_os = "linux"))]
pub fn install_castle_table() -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// GF1 deny-all safety net: force `<castle_table>` to a fail-CLOSED base output
/// chain (`policy drop`, no rules) in one atomic transaction. See
/// [`linux::install_deny_all_safety_net_impl`]. Used by the reclaim/acquire path
/// when the daemon's authenticated ownership journal proves it owned a table
/// this boot but the live table has been LOST or has DRIFTED off its captured
/// identity: deny-all is installed BEFORE the acquisition refuses, so the loop
/// is fail-closed and `policy accept` is never left in force for a live agent.
#[cfg(target_os = "linux")]
pub fn install_deny_all_safety_net(scope: &SafetyNetScope) -> Result<(), NftablesError> {
    linux::install_deny_all_safety_net_impl(scope)
}

#[cfg(not(target_os = "linux"))]
pub fn install_deny_all_safety_net(_scope: &SafetyNetScope) -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// GF1.1: whether the LIVE table is exactly this daemon's deny-all safety net.
/// See [`linux::live_table_is_deny_all_safety_net_impl`].
#[cfg(target_os = "linux")]
pub fn live_table_is_deny_all_safety_net() -> Result<bool, NftablesError> {
    linux::live_table_is_deny_all_safety_net_impl()
}

#[cfg(target_os = "linux")]
pub fn live_net_covers_attempt(scope: &SafetyNetScope) -> Result<bool, NftablesError> {
    linux::live_net_covers_attempt_impl(scope)
}

#[cfg(not(target_os = "linux"))]
pub fn live_net_covers_attempt(_scope: &SafetyNetScope) -> Result<bool, NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

#[cfg(not(target_os = "linux"))]
pub fn live_table_is_deny_all_safety_net() -> Result<bool, NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// D3 fix round: fetch the live castle table's raw JSON inventory.
/// See [`linux::live_castle_table_json_impl`]. Crate-private: consumed by both
/// disarm arms (`ReclaimOwned` and `FinalizeInterrupted`) in
/// `runtime_providers.rs`, and the recogniser above stays the only authority
/// for the net's shape. Gated `any(target_os = "linux", test)`, matching this
/// crate's convention for a Linux-only production surface that a cross-platform
/// test suite still needs to name (its own off-Linux test below is the
/// reachability anchor that keeps that build's dead-code check honest, rather
/// than exempting the function from the check).
#[cfg(target_os = "linux")]
pub(crate) fn live_castle_table_json() -> Result<String, NftablesError> {
    linux::live_castle_table_json_impl()
}

#[cfg(all(not(target_os = "linux"), test))]
pub(crate) fn live_castle_table_json() -> Result<String, NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// GF1.1 recovery: atomically reset the deny-all net to a fresh owned table
/// stamped `new_marker`. See [`linux::atomic_reset_deny_all_net_to_fresh_owned_impl`].
#[cfg(target_os = "linux")]
pub fn atomic_reset_deny_all_net_to_fresh_owned(new_marker: &str) -> Result<(), NftablesError> {
    linux::atomic_reset_deny_all_net_to_fresh_owned_impl(new_marker)
}

#[cfg(not(target_os = "linux"))]
pub fn atomic_reset_deny_all_net_to_fresh_owned(_new_marker: &str) -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// GF1.2 last-resort escalation: delete the `sanctuary-castle` table by name.
/// See [`linux::force_delete_castle_table_by_name_impl`].
#[cfg(target_os = "linux")]
pub fn force_delete_castle_table_by_name() -> Result<(), NftablesError> {
    linux::force_delete_castle_table_by_name_impl()
}

#[cfg(not(target_os = "linux"))]
pub fn force_delete_castle_table_by_name() -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Create the `sanctuary-castle` table AND its base output chain in ONE atomic
/// `create` transaction (nft's fail-on-exists verbs), propagating any error.
/// Unlike [`install_castle_table`] (idempotent `add` adopt-or-create), this
/// NEVER touches a pre-existing table: `create` fails the whole transaction if
/// the table already exists, so a `sanctuary-castle` table this acquisition did
/// not create is refused, never mutated or clobbered. `marker` is stamped as the
/// table comment so ownership can later be proven by nonce. (blocker 1)
#[cfg(target_os = "linux")]
pub fn create_castle_table_exclusive(marker: &str) -> Result<(), NftablesError> {
    linux::create_castle_table_exclusive_impl(marker)
}

#[cfg(not(target_os = "linux"))]
pub fn create_castle_table_exclusive(_marker: &str) -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Capture the exact owned identity (table + base-chain handles, marker) right
/// after a successful [`create_castle_table_exclusive`], requiring the live
/// marker to equal `expected_marker`. (blocker 3)
#[cfg(target_os = "linux")]
pub fn capture_owned_castle_table(
    expected_marker: &str,
) -> Result<CastleTableOwnership, NftablesError> {
    linux::capture_owned_castle_table_impl(expected_marker)
}

#[cfg(not(target_os = "linux"))]
pub fn capture_owned_castle_table(
    _expected_marker: &str,
) -> Result<CastleTableOwnership, NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Verify the live table is STILL exactly the captured owned identity (same
/// handles, marker, and pristine shape). Returns [`NftablesError::ForeignState`]
/// when a same-name replacement, mutation, injected rule, or extra chain has
/// drifted the table off its owned identity, so readiness withdraws. (blocker 2)
#[cfg(target_os = "linux")]
pub fn verify_owned_castle_table(
    ownership: &CastleTableOwnership,
    expectation: &ExpectedAgentBinding,
) -> Result<(), NftablesError> {
    linux::verify_owned_castle_table_impl(ownership, expectation).map(|_| ())
}

#[cfg(not(target_os = "linux"))]
pub fn verify_owned_castle_table(
    _ownership: &CastleTableOwnership,
    _expectation: &ExpectedAgentBinding,
) -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Verify the exact live inventory and only then rebuild the process-local
/// packet-mark registry needed to reclaim a preserved multi-agent table after
/// restart. This is deliberately separate from the pure health/parser path.
#[cfg(target_os = "linux")]
pub(crate) fn verify_and_register_owned_table_for_reclaim(
    ownership: &CastleTableOwnership,
    expectation: &ExpectedAgentBinding,
) -> Result<(), NftablesError> {
    let agent_ids = linux::verify_owned_castle_table_impl(ownership, expectation)?;
    for agent_id in agent_ids {
        crate::nfqueue::register_agent_mark(&agent_id);
    }
    Ok(())
}

/// Delete ONLY the exact captured owned table via a handle-qualified delete,
/// after re-verifying the live identity still matches. Refuses (does not delete)
/// if the identity has drifted, so a foreign table squatting the name is never
/// clobbered. (blocker 2/3)
#[cfg(target_os = "linux")]
pub fn remove_owned_castle_table(
    ownership: &CastleTableOwnership,
    expectation: &ExpectedAgentBinding,
) -> Result<(), NftablesError> {
    linux::remove_owned_castle_table_impl(ownership, expectation)
}

#[cfg(not(target_os = "linux"))]
pub fn remove_owned_castle_table(
    _ownership: &CastleTableOwnership,
    _expectation: &ExpectedAgentBinding,
) -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Load a ruleset for one agent's uid. Atomic replace on the per-agent chain;
/// existing connections preserved per nftables atomic-replace semantics. Also
/// installs (or refreshes) the jump rule in the base `output` chain that gates
/// entry into the per-agent chain on `meta skuid <uid>`. Without that jump rule
/// the per-agent chain is a dead chain and the kernel never consults it.
///
/// `binding` carries the manifest-signed uid and the ceiling it was admitted
/// under; see [`AgentUidBinding`].
///
/// `receipt` is the WRITE-AHEAD proof that this uid is already durably recorded in
/// this boot's confined history. It is a required argument rather than a convention:
/// the kernel must never bind a uid the journal does not yet name, because a crash
/// between the two would leave a live agent whose uid no later start can recover, and
/// the safety net would then never deny it. A failed persist yields no receipt, so the
/// bind is unreachable and the caller keeps its prior good policy with no kernel step.
/// Must match `WriteAheadReceipt` in `src/ownership_journal.rs`.
#[cfg(target_os = "linux")]
pub fn load_agent_ruleset(
    id: &AgentRulesetId,
    ruleset: &str,
    binding: AgentUidBinding,
    receipt: crate::ownership_journal::WriteAheadReceipt,
) -> Result<(), NftablesError> {
    receipt_covers_binding(&binding, receipt)?;
    linux::load_agent_ruleset_impl(id, ruleset, binding)
}

#[cfg(not(target_os = "linux"))]
pub fn load_agent_ruleset(
    _id: &AgentRulesetId,
    _ruleset: &str,
    _binding: AgentUidBinding,
    _receipt: crate::ownership_journal::WriteAheadReceipt,
) -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Refuse a receipt that does not cover the uid being bound.
///
/// Holding SOME receipt is not the property that matters; holding one for THIS uid is.
/// Without this check a caller with a receipt for an already-persisted uid could bind a
/// different, unrecorded one.
///
/// Gated to Linux exactly like its two callers, the per-agent bind wrappers, so an
/// ungated definition is not a dead-code diagnostic under `clippy -D warnings` on the
/// macOS dev build.
#[cfg(target_os = "linux")]
fn receipt_covers_binding(
    binding: &AgentUidBinding,
    receipt: crate::ownership_journal::WriteAheadReceipt,
) -> Result<(), NftablesError> {
    if receipt.uid() != binding.agent_uid {
        return Err(NftablesError::InvocationFailed(format!(
            "the write-ahead proof covers uid {} but the binding names uid {}; the journal \
             must record the uid a kernel rule is about to bind",
            receipt.uid(),
            binding.agent_uid
        )));
    }
    Ok(())
}

/// Replace an agent ruleset with a fail-closed drop chain and atomically wire
/// the uid jump to that chain. Used to park an agent at deny while its binding
/// is replaced, so no window exists in which its packets reach `policy accept`.
///
/// Takes the same write-ahead proof as [`load_agent_ruleset`]: this path also installs
/// a jump keyed on the uid, so the uid becomes live in the kernel and must be recorded
/// first even though the chain it reaches drops.
#[cfg(target_os = "linux")]
pub fn load_agent_fail_closed_ruleset(
    id: &AgentRulesetId,
    binding: AgentUidBinding,
    receipt: crate::ownership_journal::WriteAheadReceipt,
) -> Result<(), NftablesError> {
    receipt_covers_binding(&binding, receipt)?;
    linux::load_agent_fail_closed_ruleset_impl(id, binding)
}

#[cfg(not(target_os = "linux"))]
pub fn load_agent_fail_closed_ruleset(
    _id: &AgentRulesetId,
    _binding: AgentUidBinding,
    _receipt: crate::ownership_journal::WriteAheadReceipt,
) -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Remove an agent's ruleset (called on agent shutdown / unwrap). Removes
/// the base-chain jump rule first so it does not dangle pointing at a
/// deleted chain, then flushes and deletes the per-agent chain.
#[cfg(target_os = "linux")]
pub fn remove_agent_ruleset(id: &AgentRulesetId) -> Result<(), NftablesError> {
    linux::remove_agent_ruleset_impl(id)
}

#[cfg(not(target_os = "linux"))]
pub fn remove_agent_ruleset(_id: &AgentRulesetId) -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Install the jump rule from the base `output` chain into the per-agent
/// chain, gated on `meta skuid <uid>`. Idempotent: a prior jump rule for the
/// same agent is removed (handle-based delete) before the new one is added.
///
/// Most callers should use [`load_agent_ruleset`], which combines the
/// per-agent chain rules with the jump-rule wiring in one call. This granular
/// surface is exposed for binding code that needs to refresh the jump rule
/// independently.
#[cfg(target_os = "linux")]
pub fn install_agent_jump_rule(
    id: &AgentRulesetId,
    binding: AgentUidBinding,
) -> Result<(), NftablesError> {
    if castle_table() == CASTLE_TABLE {
        return Err(NftablesError::InvocationFailed(
            "standalone production jump mutation is disabled; use atomic load_agent_ruleset"
                .to_string(),
        ));
    }
    linux::install_agent_jump_rule_impl(id, binding)
}

#[cfg(not(target_os = "linux"))]
pub fn install_agent_jump_rule(
    _id: &AgentRulesetId,
    _binding: AgentUidBinding,
) -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Remove the jump rule from the base `output` chain that targets this
/// agent's per-agent chain. Idempotent: zero matching rules returns
/// `Ok(())`.
#[cfg(target_os = "linux")]
pub fn remove_agent_jump_rule(id: &AgentRulesetId) -> Result<(), NftablesError> {
    if castle_table() == CASTLE_TABLE {
        return Err(NftablesError::InvocationFailed(
            "standalone production jump mutation is disabled; use atomic load/remove_agent_ruleset"
                .to_string(),
        ));
    }
    linux::remove_agent_jump_rule_impl(id)
}

#[cfg(not(target_os = "linux"))]
pub fn remove_agent_jump_rule(_id: &AgentRulesetId) -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// List current agent rulesets in `sanctuary-castle`.
#[cfg(target_os = "linux")]
pub fn list_agent_rulesets() -> Result<Vec<String>, NftablesError> {
    linux::list_agent_rulesets_impl()
}

#[cfg(not(target_os = "linux"))]
pub fn list_agent_rulesets() -> Result<Vec<String>, NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Remove the entire `sanctuary-castle` table. Used during daemon shutdown
/// cleanup or in tests.
#[cfg(target_os = "linux")]
pub fn remove_castle_table() -> Result<(), NftablesError> {
    if castle_table() == CASTLE_TABLE {
        return Err(NftablesError::InvocationFailed(
            "name-only production table removal is disabled; use authenticated --disarm"
                .to_string(),
        ));
    }
    linux::remove_castle_table_impl()
}

#[cfg(not(target_os = "linux"))]
pub fn remove_castle_table() -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Check whether the sanctuary-castle table exists.
#[cfg(target_os = "linux")]
pub fn table_exists() -> Result<bool, NftablesError> {
    linux::table_exists_impl()
}

#[cfg(not(target_os = "linux"))]
pub fn table_exists() -> Result<bool, NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Verify the installed `sanctuary-castle` table has the exact base output-chain
/// shape this daemon installs (`type filter hook output priority 0 ;
/// policy accept ;`). Returns [`NftablesError::ForeignState`] when a table by
/// that name exists but does not match, so the enforcement runtime refuses to
/// adopt or clobber another owner's state rather than reporting ready over it.
/// This is the readiness gate the nftables component uses after install.
#[cfg(target_os = "linux")]
pub fn verify_castle_table_shape() -> Result<(), NftablesError> {
    linux::verify_castle_table_shape_impl()
}

#[cfg(not(target_os = "linux"))]
pub fn verify_castle_table_shape() -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Linux L2 deliberately performs no per-rule text lowering.
///
/// Every packet is sent to the typed Rust evaluator, which is the only place
/// where signed rule order, scope, every match axis, prompting, and audit/WAL
/// coupling can be evaluated together.  Emitting even a syntactically safe
/// static accept/drop fragment would allow a later, higher-priority rule to be
/// bypassed and would split first-match semantics across two engines.  Keeping
/// this helper total and inert also removes signed strings from the privileged
/// nft script construction boundary.
pub fn rule_to_nft_expr(_rule: &crate::policy::AllowlistRule) -> Vec<NftRuleFragment> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_skuid_value_accepts_only_a_bare_integer_uid() {
        // The P0 probe on nft 1.0.9 showed `meta skuid <uid>` listing as a bare
        // integer in both text and JSON form, for a uid with an account and one
        // without. This pins the parser to exactly that shape: a NAME, a string
        // spelling of the number, a float, a nested range, or uid 0 are all
        // refused, so a newer nft that renders names cannot be silently adopted.
        let ok = serde_json::json!({
            "match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": 4242}
        });
        assert_eq!(parse_skuid_value(&ok), Some(4242));

        let by_name = serde_json::json!({
            "match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": "sanctuary-agent"}
        });
        assert!(
            parse_skuid_value(&by_name).is_none(),
            "an account NAME must be refused; resolving it would make the kernel \
             binding depend on a mutable /etc/passwd"
        );
        let stringified = serde_json::json!({
            "match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": "4242"}
        });
        assert!(
            parse_skuid_value(&stringified).is_none(),
            "string uid refused"
        );
        let root = serde_json::json!({
            "match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": 0}
        });
        assert!(
            parse_skuid_value(&root).is_none(),
            "uid 0 is root and is never a confined agent binding"
        );
        let out_of_range = serde_json::json!({
            "match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": 4_294_967_296u64}
        });
        assert!(
            parse_skuid_value(&out_of_range).is_none(),
            "a value past u32 is not a uid"
        );

        // A different meta key, an extra key, or a non-equality operator is a
        // foreign match, not this daemon's binding.
        let wrong_key = serde_json::json!({
            "match": {"op": "==", "left": {"meta": {"key": "skgid"}}, "right": 4242}
        });
        assert!(
            parse_skuid_value(&wrong_key).is_none(),
            "skgid is not skuid"
        );
        let extra_key = serde_json::json!({
            "match": {"op": "==", "left": {"meta": {"key": "skuid", "foo": 1}}, "right": 4242}
        });
        assert!(
            parse_skuid_value(&extra_key).is_none(),
            "extra meta key refused"
        );
        let not_equality = serde_json::json!({
            "match": {"op": "!=", "left": {"meta": {"key": "skuid"}}, "right": 4242}
        });
        assert!(
            parse_skuid_value(&not_equality).is_none(),
            "non-== op refused"
        );
        let socket_shape = serde_json::json!({
            "match": {"op": "==", "left": {"socket": {"key": "cgroupv2"}}, "right": "system.slice"}
        });
        assert!(
            parse_skuid_value(&socket_shape).is_none(),
            "the retired cgroup match shape must not parse as a uid binding"
        );
    }

    #[test]
    fn agent_uid_seal_is_bound_to_fortress_agent_and_uid() {
        // The seal is a consistency check, not authority, but it must at least be
        // a FUNCTION of all three inputs: a seal that ignored the fortress or the
        // agent would let a rule sealed for one binding verify under another.
        let base = agent_uid_seal("fortress-a", "agent-one", 4242);
        assert_eq!(base.len(), AGENT_UID_SEAL_HEX_LEN);
        assert!(base.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(base, agent_uid_seal("fortress-b", "agent-one", 4242));
        assert_ne!(base, agent_uid_seal("fortress-a", "agent-two", 4242));
        assert_ne!(base, agent_uid_seal("fortress-a", "agent-one", 4243));
        assert_eq!(base, agent_uid_seal("fortress-a", "agent-one", 4242));
        // NUL separation, not concatenation: the shifted-boundary pair below would
        // collide under a bare concatenation of the three fields.
        assert_ne!(
            agent_uid_seal("fortress", "a-agent", 1000),
            agent_uid_seal("fortressa", "-agent", 1000)
        );
    }

    #[test]
    fn max_agent_id_len_leaves_every_sealed_comment_inside_the_nft_cap() {
        // The derivation, checked rather than asserted by comment: a
        // worst-case marker + role + agent id + seal must fit nft's comment cap,
        // and the queue role must be the binding one.
        let marker = format!(
            "{OWNER_MARKER_PREFIX}{}",
            "a".repeat(OWNER_MARKER_NONCE_HEX_LEN)
        );
        let agent_id = "a".repeat(MAX_AGENT_ID_LEN);
        let seal = agent_uid_seal("fortress-id", &agent_id, 4242);
        for role in [":queue:", ":jump:"] {
            let comment = format!("{marker}{role}{agent_id}{AGENT_UID_SEAL_INFIX}{seal}");
            assert!(
                comment.len() <= NFT_RULE_COMMENT_MAX_LEN,
                "{role} comment is {} bytes, over the {NFT_RULE_COMMENT_MAX_LEN}-byte cap",
                comment.len()
            );
        }
        // The fail-closed body carries no seal, so it is not the binding case.
        let fail_closed = format!("{marker}:failclosed:{agent_id}");
        assert!(fail_closed.len() <= NFT_RULE_COMMENT_MAX_LEN);
        // One more byte of agent id would overflow the queue comment: the budget
        // is tight, so this is a real bound and not a loose guess.
        let over = format!(
            "{marker}{LONGEST_SEALED_ROLE_INFIX}{}{AGENT_UID_SEAL_INFIX}{seal}",
            "a".repeat(MAX_AGENT_ID_LEN + 1)
        );
        assert!(over.len() > NFT_RULE_COMMENT_MAX_LEN);
    }

    use crate::policy::{AllowlistRule, RuleDisposition, RuleMatch, RuleScope};

    // ---- nft binary resolution: absolute-only, no PATH fallback -------------

    #[test]
    fn nft_candidate_paths_are_absolute_with_no_bare_name_fallback() {
        // blocker 9: the candidate list must be absolute-only. A bare `nft`
        // entry would reintroduce PATH resolution for a root daemon's
        // enforcement binary.
        for p in NFT_ABSOLUTE_PATHS {
            assert!(p.starts_with('/'), "nft candidate must be absolute: {p}");
        }
        assert!(
            !NFT_ABSOLUTE_PATHS.contains(&"nft"),
            "no bare-name PATH fallback allowed in the candidate list"
        );
        assert_eq!(
            NFT_ABSOLUTE_PATHS,
            ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"]
        );
    }

    #[test]
    fn resolve_nft_binary_picks_first_executable_and_never_a_bare_name() {
        // None executable -> None (no PATH fallback resurrects a bare `nft`).
        assert_eq!(resolve_nft_binary(&NFT_ABSOLUTE_PATHS, |_| false), None);
        // Only /sbin/nft executable -> picks it, not a PATH search.
        assert_eq!(
            resolve_nft_binary(&NFT_ABSOLUTE_PATHS, |p| p == "/sbin/nft"),
            Some("/sbin/nft")
        );
        // Arch/Omarchy layout: only /usr/bin/nft present -> resolves it, so the
        // daemon activates on Arch instead of failing to find its enforcement
        // binary. (Arch usr-merges sbin into bin, so nft ships under /usr/bin.)
        assert_eq!(
            resolve_nft_binary(&NFT_ABSOLUTE_PATHS, |p| p == "/usr/bin/nft"),
            Some("/usr/bin/nft")
        );
        // First candidate wins when several are executable: the sbin path is
        // preferred over the Arch /usr/bin path when both exist.
        assert_eq!(
            resolve_nft_binary(&NFT_ABSOLUTE_PATHS, |_| true),
            Some("/usr/sbin/nft")
        );
        assert_eq!(
            resolve_nft_binary(&NFT_ABSOLUTE_PATHS, |p| p == "/sbin/nft"
                || p == "/usr/bin/nft"),
            Some("/sbin/nft"),
            "sbin nft takes precedence over the Arch /usr/bin nft"
        );
    }

    #[cfg(unix)]
    #[test]
    fn is_executable_file_requires_a_regular_file_with_an_exec_bit() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().unwrap();
        let f = dir.path().join("tool");
        std::fs::write(&f, b"#!/bin/sh\n").unwrap();
        let p = f.to_str().unwrap();
        // A non-executable regular file is rejected.
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!is_executable_file(p));
        // With an exec bit it is accepted.
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(is_executable_file(p));
        // A directory is not an executable file, and a missing path is rejected.
        assert!(!is_executable_file(dir.path().to_str().unwrap()));
        assert!(!is_executable_file(
            dir.path().join("missing").to_str().unwrap()
        ));
    }

    // ---- foreign-table detection via structured nft -j JSON (no kernel) -----

    /// A realistic `nft -j list table inet sanctuary-castle` document for THIS
    /// daemon's exact base output chain.
    fn ours_json() -> &'static str {
        r#"{"nftables":[
          {"metainfo":{"version":"1.0.9","release_name":"Old Doc Yak","json_schema_version":1}},
          {"table":{"family":"inet","name":"sanctuary-castle","handle":2}},
          {"chain":{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
            "type":"filter","hook":"output","prio":0,"policy":"accept"}}
        ]}"#
    }

    #[test]
    fn our_table_json_is_recognized() {
        assert!(output_chain_shape_is_ours_json(ours_json()));
    }

    #[test]
    fn foreign_drop_policy_json_is_refused() {
        let json = r#"{"nftables":[
          {"table":{"family":"inet","name":"sanctuary-castle","handle":2}},
          {"chain":{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
            "type":"filter","hook":"output","prio":0,"policy":"drop"}}
        ]}"#;
        assert!(!output_chain_shape_is_ours_json(json));
    }

    #[test]
    fn wrong_hook_json_is_refused() {
        // A base chain hooked on `input` is a foreign base chain, not our egress
        // output hook.
        let json = r#"{"nftables":[
          {"chain":{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
            "type":"filter","hook":"input","prio":0,"policy":"accept"}}
        ]}"#;
        assert!(!output_chain_shape_is_ours_json(json));
    }

    #[test]
    fn wrong_priority_json_is_refused() {
        let json = r#"{"nftables":[
          {"chain":{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
            "type":"filter","hook":"output","prio":10,"policy":"accept"}}
        ]}"#;
        assert!(!output_chain_shape_is_ours_json(json));
    }

    #[test]
    fn split_family_or_table_json_is_refused() {
        // Right chain name and shape, but a DIFFERENT family — a split/foreign
        // shape the substring scan could not have caught.
        let wrong_family = r#"{"nftables":[
          {"chain":{"family":"ip","table":"sanctuary-castle","name":"output","handle":1,
            "type":"filter","hook":"output","prio":0,"policy":"accept"}}
        ]}"#;
        assert!(!output_chain_shape_is_ours_json(wrong_family));
        let wrong_table = r#"{"nftables":[
          {"chain":{"family":"inet","table":"someone-else","name":"output","handle":1,
            "type":"filter","hook":"output","prio":0,"policy":"accept"}}
        ]}"#;
        assert!(!output_chain_shape_is_ours_json(wrong_table));
    }

    #[test]
    fn non_base_chain_only_json_is_refused() {
        // A same-named table whose only chain is a REGULAR (non-base, no hook)
        // chain has no egress hook: foreign state we must not enforce through.
        let json = r#"{"nftables":[
          {"table":{"family":"inet","name":"sanctuary-castle","handle":2}},
          {"chain":{"family":"inet","table":"sanctuary-castle","name":"somechain","handle":1}}
        ]}"#;
        assert!(!output_chain_shape_is_ours_json(json));
    }

    #[test]
    fn missing_type_field_json_is_refused() {
        // A base chain (has a hook) missing `type` is not our exact shape.
        let json = r#"{"nftables":[
          {"chain":{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
            "hook":"output","prio":0,"policy":"accept"}}
        ]}"#;
        assert!(!output_chain_shape_is_ours_json(json));
    }

    #[test]
    fn our_chain_plus_a_foreign_base_chain_is_refused() {
        // Our exact output chain PLUS an additional foreign base chain (an
        // `input` hook) is refusable: ANY base chain that is not ours makes the
        // table foreign/incompatible, even when ours is present.
        let json = r#"{"nftables":[
          {"table":{"family":"inet","name":"sanctuary-castle","handle":2}},
          {"chain":{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
            "type":"filter","hook":"output","prio":0,"policy":"accept"}},
          {"chain":{"family":"inet","table":"sanctuary-castle","name":"intruder","handle":3,
            "type":"filter","hook":"input","prio":0,"policy":"accept"}}
        ]}"#;
        assert!(!output_chain_shape_is_ours_json(json));
    }

    #[test]
    fn empty_or_unparseable_json_is_refused() {
        // Absent, indeterminate, unparseable all read as not-ours (refuse).
        assert!(!output_chain_shape_is_ours_json(""));
        assert!(!output_chain_shape_is_ours_json("not json at all"));
        assert!(!output_chain_shape_is_ours_json("{}"));
        assert!(!output_chain_shape_is_ours_json(r#"{"nftables":[]}"#));
        // A table object with NO chain at all -> no base chain -> refuse.
        assert!(!output_chain_shape_is_ours_json(
            r#"{"nftables":[{"table":{"family":"inet","name":"sanctuary-castle","handle":2}}]}"#
        ));
    }

    // ---- exclusive-create script: `create`, never `add` (blocker 1) --------

    #[test]
    fn exclusive_create_script_uses_create_verbs_never_add() {
        // The acquisition path MUST use nft's fail-on-exists `create` verbs so a
        // raced/foreign same-named table is refused rather than silently adopted.
        // A regression to `add` (idempotent) would reintroduce the adoption hazard.
        let marker = format!("{OWNER_MARKER_PREFIX}deadbeefdeadbeefdeadbeefdeadbeef");
        let script = build_create_castle_table_script(&marker);
        assert!(
            script.contains("create table inet sanctuary-castle"),
            "must create the table with the fail-on-exists `create` verb: {script}"
        );
        assert!(
            script.contains("create chain inet sanctuary-castle output"),
            "must create the base chain with `create`, in the same transaction: {script}"
        );
        // Hard reject `add`: an `add table`/`add chain` here is the exact
        // idempotent-adoption bug this blocker fixes.
        assert!(
            !script.contains("add table") && !script.contains("add chain"),
            "must NEVER use idempotent `add` on the acquisition path: {script}"
        );
        // Exact base output chain shape and the ownership marker comment.
        assert!(script.contains("type filter hook output priority 0 ; policy accept ;"));
        assert!(
            script.contains(&format!("comment \"{marker}\"")),
            "table must carry the ownership marker as its comment: {script}"
        );
    }

    // ---- exact owned-identity parse (blocker 2) ----------------------------

    fn owned_json(table_handle: u64, chain_handle: u64, marker: &str) -> String {
        format!(
            r#"{{"nftables":[
              {{"metainfo":{{"version":"1.0.9","json_schema_version":1}}}},
              {{"table":{{"family":"inet","name":"sanctuary-castle","handle":{table_handle},
                "comment":"{marker}"}}}},
              {{"chain":{{"family":"inet","table":"sanctuary-castle","name":"output",
                "handle":{chain_handle},"type":"filter","hook":"output","prio":0,
                "policy":"accept"}}}}
            ]}}"#
        )
    }

    #[test]
    fn owned_identity_parses_handles_and_marker() {
        let marker = format!("{OWNER_MARKER_PREFIX}0123456789abcdef0123456789abcdef");
        let owned = parse_owned_table_identity(&owned_json(2, 1, &marker), &fixture_expectation())
            .expect("owned");
        assert_eq!(
            owned,
            CastleTableOwnership {
                table_handle: 2,
                base_chain_handle: 1,
                marker,
            }
        );
    }

    /// The fortress every owned-agent fixture below seals under. A single
    /// constant so a test that means to change the FORTRESS has to say so.
    const FIXTURE_FORTRESS: &str = "fixture-fortress";
    /// The uid every owned-agent fixture binds. Above any plausible system-uid
    /// ceiling, so it is a legitimate confined-agent uid.
    const FIXTURE_AGENT_UID: u32 = 4242;

    /// The trusted expectation matching the fixtures: what a healthy reclaim or
    /// health poll would carry.
    fn fixture_expectation() -> ExpectedAgentBinding {
        ExpectedAgentBinding::Confined {
            fortress_id: FIXTURE_FORTRESS.to_string(),
            agent_uid: FIXTURE_AGENT_UID,
        }
    }

    fn owned_agent_json(marker: &str, include_body: bool, include_jump: bool) -> String {
        owned_agent_json_with_uid(marker, include_body, include_jump, FIXTURE_AGENT_UID)
    }

    /// An owned inventory whose per-agent rules bind `uid`, sealed CORRECTLY for
    /// that uid. Sealing correctly is the point: a test that wants to exercise
    /// the trusted-uid comparison must not be able to pass by accident because
    /// the seal caught the mismatch first.
    fn owned_agent_json_with_uid(
        marker: &str,
        include_body: bool,
        include_jump: bool,
        uid: u32,
    ) -> String {
        let chain = agent_chain_name("agent-one");
        let mark = crate::nfqueue::agent_mark("agent-one");
        // The fixture mirrors the exact `agent_uid_seal` the production emission
        // site writes: seal input is (fortress, agent, uid), and the parser
        // recomputes it from the LIVE match value.
        let seal = agent_uid_seal(FIXTURE_FORTRESS, "agent-one", uid);
        let skuid_match =
            format!(r#""match":{{"op":"==","left":{{"meta":{{"key":"skuid"}}}},"right":{uid}}}"#);
        let body = if include_body {
            format!(
                r#",{{"rule":{{"family":"inet","table":"sanctuary-castle","chain":"{chain}","handle":10,"comment":"{marker}:queue:agent-one:uid:{seal}","expr":[{{{skuid_match}}},{{"mangle":{{"key":{{"meta":{{"key":"mark"}}}},"value":{mark}}}}},{{"queue":{{"num":0}}}}]}}}}"#
            )
        } else {
            String::new()
        };
        let jump = if include_jump {
            format!(
                r#",{{"rule":{{"family":"inet","table":"sanctuary-castle","chain":"output","handle":11,"comment":"{marker}:jump:agent-one:uid:{seal}","expr":[{{{skuid_match}}},{{"goto":{{"target":"{chain}"}}}}]}}}}"#
            )
        } else {
            String::new()
        };
        format!(
            r#"{{"nftables":[
              {{"table":{{"family":"inet","name":"sanctuary-castle","handle":2,"comment":"{marker}"}}}},
              {{"chain":{{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
                "type":"filter","hook":"output","prio":0,"policy":"accept"}}}},
              {{"chain":{{"family":"inet","table":"sanctuary-castle","name":"{chain}","handle":9,
                "comment":"{marker}:agent:agent-one"}}}}{body}{jump}
            ]}}"#
        )
    }

    fn fixture_marker() -> String {
        format!("{OWNER_MARKER_PREFIX}0123456789abcdef0123456789abcdef")
    }

    /// An owned inventory carrying an ARBITRARY set of `(agent_id, uid)`
    /// bindings, each correctly sealed. The set rule's whole subject is
    /// cardinality and agent identity, so the fixture has to be able to build
    /// tables the single-agent fixture above cannot: two chains for one uid, and
    /// a chain under a foreign agent id bound to the admitted uid. Both are
    /// shapes the frozen parser ACCEPTS, which is why the set rule exists.
    fn owned_table_with_bindings(marker: &str, bindings: &[(&str, u32)]) -> String {
        let mut chains = String::new();
        let mut rules = String::new();
        // Handles are distinct per object; the parser only compares the table and
        // base-chain handles, so the per-agent values only have to be unique.
        let mut next_handle = 9u64;
        for (agent_id, uid) in bindings {
            let chain = agent_chain_name(agent_id);
            let mark = crate::nfqueue::agent_mark(agent_id);
            let seal = agent_uid_seal(FIXTURE_FORTRESS, agent_id, *uid);
            let skuid_match = format!(
                r#""match":{{"op":"==","left":{{"meta":{{"key":"skuid"}}}},"right":{uid}}}"#
            );
            chains.push_str(&format!(
                r#",{{"chain":{{"family":"inet","table":"sanctuary-castle","name":"{chain}","handle":{next_handle},"comment":"{marker}:agent:{agent_id}"}}}}"#
            ));
            next_handle += 1;
            rules.push_str(&format!(
                r#",{{"rule":{{"family":"inet","table":"sanctuary-castle","chain":"{chain}","handle":{next_handle},"comment":"{marker}:queue:{agent_id}:uid:{seal}","expr":[{{{skuid_match}}},{{"mangle":{{"key":{{"meta":{{"key":"mark"}}}},"value":{mark}}}}},{{"queue":{{"num":0}}}}]}}}}"#
            ));
            next_handle += 1;
            rules.push_str(&format!(
                r#",{{"rule":{{"family":"inet","table":"sanctuary-castle","chain":"output","handle":{next_handle},"comment":"{marker}:jump:{agent_id}:uid:{seal}","expr":[{{{skuid_match}}},{{"goto":{{"target":"{chain}"}}}}]}}}}"#
            ));
            next_handle += 1;
        }
        format!(
            r#"{{"nftables":[
              {{"table":{{"family":"inet","name":"sanctuary-castle","handle":2,"comment":"{marker}"}}}},
              {{"chain":{{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
                "type":"filter","hook":"output","prio":0,"policy":"accept"}}}}{chains}{rules}
            ]}}"#
        )
    }

    fn fixture_ownership(marker: &str) -> CastleTableOwnership {
        CastleTableOwnership {
            table_handle: 2,
            base_chain_handle: 1,
            marker: marker.to_string(),
        }
    }

    fn confined(uid: u32) -> ExpectedAgentBinding {
        ExpectedAgentBinding::Confined {
            fortress_id: FIXTURE_FORTRESS.to_string(),
            agent_uid: uid,
        }
    }

    #[test]
    fn the_set_rule_adopts_exactly_the_required_singleton() {
        let marker = fixture_marker();
        let uid = 60123;
        let json = owned_table_with_bindings(&marker, &[(&confined_agent_id(uid), uid)]);
        let set =
            owned_table_binding_set_from_json(&json, &fixture_ownership(&marker), &confined(uid))
                .expect("the owned shape passes");
        assert!(matches!(set, OwnedBindingSet::Verified(_)));
        assert_eq!(
            set.inventory().bindings,
            vec![(confined_agent_id(uid), uid)]
        );
    }

    #[test]
    fn the_set_rule_refuses_a_foreign_agent_id_bound_to_the_admitted_uid() {
        let marker = fixture_marker();
        let uid = 60123;
        // The frozen parser compares the UID only, so this table is `Verified`
        // there. The set rule is the only thing that refuses it.
        let json = owned_table_with_bindings(&marker, &[("shadow", uid)]);
        assert!(matches!(
            parse_owned_table_inventory_phases(&json, &confined(uid)).unwrap(),
            OwnedInventoryPhases::Verified(_)
        ));
        let set =
            owned_table_binding_set_from_json(&json, &fixture_ownership(&marker), &confined(uid))
                .unwrap();
        match set {
            OwnedBindingSet::UidMismatch { inventory, .. } => {
                // The inventory survives the refusal: the safety net's deny set
                // needs the uid a drifted-but-ours table routes.
                assert_eq!(inventory.bindings, vec![("shadow".to_string(), uid)]);
            }
            OwnedBindingSet::Verified(_) => {
                panic!("a chain under another agent id must not be adopted")
            }
        }
    }

    #[test]
    fn the_set_rule_refuses_two_chains_for_the_same_uid() {
        let marker = fixture_marker();
        let uid = 60123;
        let json =
            owned_table_with_bindings(&marker, &[(&confined_agent_id(uid), uid), ("shadow", uid)]);
        let set =
            owned_table_binding_set_from_json(&json, &fixture_ownership(&marker), &confined(uid))
                .unwrap();
        assert!(matches!(set, OwnedBindingSet::UidMismatch { .. }));
        assert_eq!(set.inventory().bindings.len(), 2);
    }

    #[test]
    fn the_set_rule_reads_an_empty_table_as_a_mismatch_under_confined_and_verified_under_none() {
        let marker = fixture_marker();
        let json = owned_table_with_bindings(&marker, &[]);
        // Under a confining manifest an empty set is NOT the required set. Health
        // reads that as a proven loss; acquisition reads the same inventory and
        // installs.
        let set =
            owned_table_binding_set_from_json(&json, &fixture_ownership(&marker), &confined(60123))
                .unwrap();
        assert!(matches!(set, OwnedBindingSet::UidMismatch { .. }));
        assert!(set.inventory().bindings.is_empty());
        // Under a manifest that confines nobody, empty IS the required set.
        assert!(matches!(
            owned_table_binding_set_from_json(
                &json,
                &fixture_ownership(&marker),
                &ExpectedAgentBinding::NoneConfined,
            )
            .unwrap(),
            OwnedBindingSet::Verified(_)
        ));
    }

    #[test]
    fn the_set_rule_refuses_a_table_whose_handles_drifted() {
        let marker = fixture_marker();
        let uid = 60123;
        let json = owned_table_with_bindings(&marker, &[(&confined_agent_id(uid), uid)]);
        let wrong = CastleTableOwnership {
            table_handle: 999,
            base_chain_handle: 1,
            marker: marker.clone(),
        };
        assert!(matches!(
            owned_table_binding_set_from_json(&json, &wrong, &confined(uid)),
            Err(NftablesError::ForeignState(_))
        ));
    }

    #[test]
    fn the_set_rule_keeps_the_parsers_wording_for_a_uid_drift() {
        let marker = fixture_marker();
        // The live binding routes a uid the manifest no longer admits.
        let json = owned_table_with_bindings(&marker, &[(&confined_agent_id(60123), 60123)]);
        let set =
            owned_table_binding_set_from_json(&json, &fixture_ownership(&marker), &confined(60125))
                .unwrap();
        match set {
            OwnedBindingSet::UidMismatch { detail, inventory } => {
                assert!(
                    detail.contains("is not the uid the current signed manifest confines"),
                    "the two layers must not describe one drift differently: {detail}"
                );
                assert_eq!(inventory.bindings, vec![(confined_agent_id(60123), 60123)]);
            }
            OwnedBindingSet::Verified(_) => panic!("a drifted uid must not be adopted"),
        }
    }

    #[test]
    fn the_confined_agent_id_derivation_is_one_function() {
        assert_eq!(confined_agent_id(60123), "uid-60123");
        assert!(confined_agent_id(0).starts_with(CONFINED_AGENT_ID_PREFIX));
    }

    #[test]
    fn ordinary_inventory_parsing_is_pure_and_reclaim_metadata_is_complete() {
        let marker = fixture_marker();
        let mark = crate::nfqueue::agent_mark("agent-one");
        let before = crate::nfqueue::resolve_agent_mark(mark);
        let parsed = parse_owned_table_inventory_phases(
            &owned_agent_json(&marker, true, true),
            &fixture_expectation(),
        )
        .expect("complete inventory");
        let parsed = match parsed {
            OwnedInventoryPhases::Verified(inventory) => inventory,
            OwnedInventoryPhases::UidMismatch { .. } => {
                panic!("this fixture matches the manifest, so phase two passes")
            }
        };
        assert_eq!(parsed.agent_ids, vec!["agent-one".to_string()]);
        assert_eq!(
            crate::nfqueue::resolve_agent_mark(mark),
            before,
            "health/parser calls must not mutate global NFQUEUE attribution; only the \
             serialized authenticated reclaim path may restore these IDs"
        );
    }

    /// The late-failure guarantee of the two-phase parse: a valid binding followed by a
    /// FOREIGN rule exposes NO partial set.
    ///
    /// A `Bindings` value is only honest if the WHOLE owned shape passed. If a partial
    /// set escaped, a caller would treat uids collected before the failure as "what this
    /// daemon's table routes" when the document was never proven to be that table.
    #[test]
    fn owned_inventory_exposes_no_partial_binding_set_on_a_late_failure() {
        let marker = fixture_marker();
        let valid = owned_agent_json(&marker, true, true);
        // Sanity: the untouched fixture DOES yield its binding, so the assertion below
        // is about the late failure and not about an empty fixture.
        assert_eq!(
            live_table_uid_bindings(&valid, &fixture_expectation(), test_overflow()),
            LiveTableBindings::Bindings(vec![FIXTURE_AGENT_UID])
        );

        // Now append a FOREIGN rule after the valid binding: an unmarked rule in our base
        // chain, which the owned shape never contains.
        let with_foreign = valid.replace(
            "\n            ]}",
            ",{\"rule\":{\"family\":\"inet\",\"table\":\"sanctuary-castle\",\"chain\":\"output\",\
             \"handle\":99,\"expr\":[{\"accept\":null}]}}\n            ]}",
        );
        assert_ne!(with_foreign, valid, "the late-failure fixture must differ");
        match live_table_uid_bindings(&with_foreign, &fixture_expectation(), test_overflow()) {
            LiveTableBindings::NotOurTable { .. } => {}
            other => panic!(
                "a document that fails phase one must yield NOTHING, not a partial set: \
                 {other:?}"
            ),
        }
    }

    /// Source (c) across its three shapes.
    #[test]
    fn live_table_uid_bindings_reads_the_owned_wall_and_both_net_shapes() {
        let ov = test_overflow();
        // THE OWNED WALL: the declared per-agent binding.
        assert_eq!(
            live_table_uid_bindings(
                &owned_agent_json(&fixture_marker(), true, true),
                &fixture_expectation(),
                ov
            ),
            LiveTableBindings::Bindings(vec![FIXTURE_AGENT_UID])
        );

        // AN OWNED WALL THAT DRIFTED off the current manifest still contributes its uids:
        // a rotated-away uid may still have live processes, so the net must deny it even
        // though the binding itself is refused for adoption.
        assert_eq!(
            live_table_uid_bindings(
                &owned_agent_json_with_uid(&fixture_marker(), true, true, 5555),
                &fixture_expectation(),
                ov
            ),
            LiveTableBindings::Bindings(vec![5555])
        );

        // THE V1 NET: no rules at all, so source (c) is EMPTY. This is distinct from
        // "not our table": the net IS ours and it names nobody.
        assert_eq!(
            live_table_uid_bindings(&v1_host_wide_listing(), &fixture_expectation(), ov),
            LiveTableBindings::Bindings(Vec::new())
        );

        // THE V2 NET: rule 1's set, which is the set currently denying traffic in the
        // kernel. Reading this as "not our table" would let a restart install a net
        // narrower than the one already in force.
        assert_eq!(
            live_table_uid_bindings(
                &v2_identity_listing(&[60123, 60124], &[60123, 60124]),
                &fixture_expectation(),
                ov
            ),
            LiveTableBindings::Bindings(vec![60123, 60124])
        );

        // A STRUCTURALLY FOREIGN table yields nothing, and that is not the same value as
        // the empty set above.
        match live_table_uid_bindings("{\"nftables\":[]}", &fixture_expectation(), ov) {
            LiveTableBindings::NotOurTable { .. } => {}
            other => panic!("a foreign document must yield nothing, got {other:?}"),
        }
    }

    /// A realistic `nft -j list ruleset` fragment for rule 1 of the deny-all
    /// identity net when the denied set names exactly ONE uid. Real nft
    /// collapses a single-member anonymous set to a bare scalar under
    /// `right`, never `{"set":[..]}`; the real-kernel witness is
    /// `integration_linux_runtime_activation.rs:1722-1725` and the sibling
    /// case in `nft_set_json_forms_are_the_shapes_the_parser_reads`
    /// (`tests/integration_gf1_recovery.rs`), not `parse_skuid_value` (that
    /// probe covers a different, always-bare rule and says nothing about a
    /// one-member SET collapsing). `net_rule_one_uids` reads only rule 1, so
    /// the fixture carries just that rule plus the table/chain wrapper the
    /// function does not inspect.
    fn net_rule_json_with_right(right_json: &str) -> String {
        format!(
            r#"{{"nftables":[
            {{"table":{{"family":"inet","name":"sanctuary-castle","handle":7}}}},
            {{"rule":{{"family":"inet","table":"sanctuary-castle","chain":"output","handle":11,
              "comment":"{identity}",
              "expr":[{{"match":{{"op":"==","left":{{"meta":{{"key":"skuid"}}}},"right":{right}}}}},
                      {{"drop":null}}]}}}}
        ]}}"#,
            identity = NET_RULE_COMMENT_IDENTITY,
            right = right_json,
        )
    }

    /// The confirmed defect: a single-uid identity rule, in the scalar form nft
    /// actually renders it, must still surface its uid. Reading only the
    /// `{"set":[..]}` array form drops this daemon's own already-installed
    /// deny-all uid from source (c) of `resolve_safety_net_scope`, and
    /// `live_table_uid_bindings`'s own comment above is explicit that
    /// undercounting here can install a net NARROWER than the one already
    /// enforcing in the kernel.
    #[test]
    fn net_rule_one_uids_reads_the_single_member_scalar_form() {
        let json = net_rule_json_with_right("60123");
        assert_eq!(
            net_rule_one_uids(&json),
            vec![60123],
            "a scalar `right` for a one-member meta skuid match must yield that uid"
        );
    }

    /// The existing multi-member array form keeps working, unsorted and with a
    /// duplicate, since the function's own contract is ascending + deduplicated.
    #[test]
    fn net_rule_one_uids_reads_the_multi_member_set_form() {
        let json = net_rule_json_with_right(r#"{"set":[60124,60123,60124]}"#);
        assert_eq!(net_rule_one_uids(&json), vec![60123, 60124]);
    }

    /// A "set" key whose own value is itself a bare scalar (rather than a
    /// one-element array) is NOT a shape any real-kernel witness records nft
    /// emitting (see `skuid_right_members`'s doc): the accepted surface is
    /// kept equal to observed nft outputs, so this speculative shape refuses
    /// exactly like the other unrecognised shapes below rather than being
    /// normalised.
    #[test]
    fn net_rule_one_uids_refuses_a_scalar_nested_under_set() {
        let json = net_rule_json_with_right(r#"{"set":60123}"#);
        assert_eq!(net_rule_one_uids(&json), Vec::<u32>::new());
    }

    /// Malformed shapes the function does not recognise must never be read as
    /// "this rule denies nobody" in a way that differs from "no such rule was
    /// found at all"; both already return the empty vec, and this test pins
    /// that the malformed cases do not instead panic or silently pick a wrong
    /// member. `{"range":[1000,2000]}` is the one listed form nft genuinely
    /// emits for `meta skuid 1000-2000`, so it is the case most worth pinning
    /// here rather than only a hand-composed name/null/object/array/float;
    /// `{"set":[60123,"root"]}` pins that ONE non-numeric member anywhere in
    /// an otherwise-valid array refuses the WHOLE match, not a partial read.
    #[test]
    fn net_rule_one_uids_refuses_unrecognised_right_shapes() {
        for right in [
            "\"sanctuary-agent\"",
            "null",
            "{}",
            "[]",
            "4.5",
            r#"{"range":[1000,2000]}"#,
            r#"{"set":[60123,"root"]}"#,
        ] {
            let json = net_rule_json_with_right(right);
            assert_eq!(
                net_rule_one_uids(&json),
                Vec::<u32>::new(),
                "unrecognised right shape {right} must not be read as any uid"
            );
        }
    }

    #[test]
    fn owned_inventory_refuses_a_uid_the_manifest_does_not_confine() {
        // THE core check of the uid migration, and the only one an actor holding
        // CAP_NET_ADMIN cannot satisfy. Here the live table is fully
        // self-consistent: both expressions bind uid 5555, both comments carry a
        // CORRECTLY recomputed seal for 5555, body and jump agree, cardinality is
        // exact, the marker is intact. Shape, seal, agreement and cardinality all
        // pass. Only the manifest expectation refuses it — which is why the seal
        // is documented as a consistency check and never as authority.
        let marker = fixture_marker();
        let other_uid = owned_agent_json_with_uid(&marker, true, true, 5555);
        // Sanity: the forgery IS internally consistent, so it would pass every
        // check that reads only the dump.
        parse_owned_table_identity(
            &other_uid,
            &ExpectedAgentBinding::SealOnly {
                fortress_id: FIXTURE_FORTRESS.to_string(),
            },
        )
        .expect("the forgery is internally consistent and passes seal-only");

        let err = parse_owned_table_identity(&other_uid, &fixture_expectation()).unwrap_err();
        assert!(
            matches!(err, NftablesError::ForeignState(_)),
            "a self-consistent binding for a uid the manifest does not confine must be \
             refused as foreign, got: {err:?}"
        );
        // The legitimate binding still parses: the check rejects ONLY the wrong uid.
        parse_owned_table_identity(
            &owned_agent_json(&marker, true, true),
            &fixture_expectation(),
        )
        .expect("the correct per-agent binding must still parse");
    }

    #[test]
    fn owned_inventory_refuses_a_live_binding_when_the_manifest_confines_no_uid() {
        // Absent is not passing. A manifest with no `agent_origin` (or a
        // non-`uid` mode) confines nobody, so a live per-agent binding is
        // something this process cannot vouch for: refuse it fail-closed rather
        // than adopt it because nothing contradicted it.
        let marker = fixture_marker();
        let err = parse_owned_table_identity(
            &owned_agent_json(&marker, true, true),
            &ExpectedAgentBinding::NoneConfined,
        )
        .unwrap_err();
        assert!(
            matches!(err, NftablesError::ForeignState(_)),
            "got: {err:?}"
        );
        // A table with NO agent binding is still fine under the same expectation:
        // that is the ordinary kernel-runtime-ready posture with nothing wrapped.
        parse_owned_table_identity(
            &owned_json(2, 1, &marker),
            &ExpectedAgentBinding::NoneConfined,
        )
        .expect("an agent-free owned table is legitimate with nothing confined");
    }

    #[test]
    fn owned_inventory_refuses_a_wrong_fortress_or_wrong_agent_seal() {
        // The seal binds (fortress, agent, uid). A binding sealed under another
        // fortress, or for another agent id, is not this fortress's owned object
        // even when the uid and the shape are right.
        let marker = fixture_marker();
        let pristine = owned_agent_json(&marker, true, true);
        let correct_seal = agent_uid_seal(FIXTURE_FORTRESS, "agent-one", FIXTURE_AGENT_UID);

        let wrong_fortress_seal =
            agent_uid_seal("some-other-fortress", "agent-one", FIXTURE_AGENT_UID);
        let forged = pristine.replace(&correct_seal, &wrong_fortress_seal);
        assert!(parse_owned_table_identity(&forged, &fixture_expectation()).is_err());

        let wrong_agent_seal = agent_uid_seal(FIXTURE_FORTRESS, "agent-two", FIXTURE_AGENT_UID);
        let forged = pristine.replace(&correct_seal, &wrong_agent_seal);
        assert!(parse_owned_table_identity(&forged, &fixture_expectation()).is_err());

        // And verifying the correct fixture under a DIFFERENT fortress fails: the
        // recompute uses the caller's fortress id, never one read from the dump.
        let other_fortress = ExpectedAgentBinding::Confined {
            fortress_id: "some-other-fortress".to_string(),
            agent_uid: FIXTURE_AGENT_UID,
        };
        assert!(parse_owned_table_identity(&pristine, &other_fortress).is_err());
    }

    #[test]
    fn owned_inventory_refuses_missing_or_forged_agent_uid_seal() {
        // A skuid-matching rule with its `:uid:` seal stripped is refused (the
        // seal is mandatory), and one whose seal does not match its own uid is
        // refused (an in-place expr mutation that forgot to also rewrite the
        // seal). Retargeted from the cgroup-path-seal case, same class.
        let marker = fixture_marker();
        let seal = agent_uid_seal(FIXTURE_FORTRESS, "agent-one", FIXTURE_AGENT_UID);
        let pristine = owned_agent_json(&marker, true, true);
        let unsealed = pristine.replace(&format!(":uid:{seal}"), "");
        assert!(parse_owned_table_identity(&unsealed, &fixture_expectation()).is_err());
        let wrong = pristine.replace(&seal, "ffffffffffffffff");
        assert!(parse_owned_table_identity(&wrong, &fixture_expectation()).is_err());
    }

    #[test]
    fn owned_inventory_refuses_an_in_place_uid_rewrite_of_one_expression() {
        // The natural in-place attack: rewrite ONE expression's uid, leave the
        // comment. Two independent checks fire — the seal no longer recomputes,
        // and body and jump no longer agree — and the test pins that the
        // DISAGREEMENT alone is caught, by using a correctly-sealed comment for
        // the rewritten value on the jump only.
        let marker = fixture_marker();
        let mut document: serde_json::Value =
            serde_json::from_str(&owned_agent_json(&marker, true, true)).unwrap();
        let items = document["nftables"].as_array_mut().unwrap();
        let jump = items
            .iter_mut()
            .find_map(|item| {
                let rule = item.get_mut("rule")?;
                (rule.get("chain")?.as_str()? == "output").then_some(rule)
            })
            .unwrap();
        jump["expr"][0]["match"]["right"] = serde_json::json!(FIXTURE_AGENT_UID + 1);
        jump["comment"] = serde_json::json!(format!(
            "{marker}:jump:agent-one:uid:{}",
            agent_uid_seal(FIXTURE_FORTRESS, "agent-one", FIXTURE_AGENT_UID + 1)
        ));
        let err =
            parse_owned_table_identity(&document.to_string(), &fixture_expectation()).unwrap_err();
        assert!(
            matches!(err, NftablesError::ForeignState(_)),
            "a body/jump uid disagreement must be refused as foreign, got: {err:?}"
        );
    }

    #[test]
    fn owned_inventory_refuses_a_non_integer_or_out_of_range_skuid_expression() {
        // A name form (a newer nft rendering `skuid` through the uid symbol
        // table) and a past-u32 value both read as foreign rather than being
        // resolved or truncated. Fail-closed: readiness withdraws and the GF1
        // deny-all net re-arms, rather than the parser guessing.
        let marker = fixture_marker();
        let pristine = owned_agent_json(&marker, true, true);
        let named = pristine.replace(
            &format!(r#""right":{FIXTURE_AGENT_UID}"#),
            r#""right":"sanctuary-agent""#,
        );
        assert!(named.contains(r#""right":"sanctuary-agent""#));
        assert!(parse_owned_table_identity(&named, &fixture_expectation()).is_err());

        let huge = pristine.replace(
            &format!(r#""right":{FIXTURE_AGENT_UID}"#),
            r#""right":4294967296"#,
        );
        assert!(parse_owned_table_identity(&huge, &fixture_expectation()).is_err());
    }

    #[test]
    fn owned_inventory_carries_no_numeric_form_cgroup_refusal() {
        // The numeric-form refusal existed ONLY because a destroyed cgroup and a
        // hostile in-place rewrite displayed identically, and a bare integer was
        // ambiguous. With a uid match an integer IS the shape, so that refusal is
        // deleted; this test pins its ABSENCE so it is not reintroduced as
        // cargo-culted defence that would refuse every legitimate binding.
        let marker = fixture_marker();
        let numeric_uid_binding = owned_agent_json_with_uid(&marker, true, true, 12345);
        parse_owned_table_identity(
            &numeric_uid_binding,
            &ExpectedAgentBinding::Confined {
                fortress_id: FIXTURE_FORTRESS.to_string(),
                agent_uid: 12345,
            },
        )
        .expect("an all-digit skuid value is the NORMAL owned shape, never a refusal trigger");
    }

    /// The overflow uid the recogniser and scope tests validate against. A real
    /// default, so the fixtures read like a host rather than like a number picked
    /// to pass.
    const TEST_HOST_OVERFLOW_UID: u32 = 65534;

    fn test_overflow() -> HostOverflowUid {
        HostOverflowUid::from_value(TEST_HOST_OVERFLOW_UID)
    }

    /// Build a `SafetyNetScope::Identity` through the only admitted path.
    fn identity_scope(uids: &[u32]) -> SafetyNetScope {
        let validated = uids
            .iter()
            .map(|&uid| {
                validate_safety_net_uid(uid, test_overflow()).expect("fixture uid is attestable")
            })
            .collect::<Vec<_>>();
        SafetyNetScope::Identity(
            ConfinedUidSet::from_validated(validated).expect("fixture set is non-empty"),
        )
    }

    /// The v1 host-wide listing: one unmarked table, one `policy drop` base
    /// chain, zero rules.
    fn v1_host_wide_listing() -> String {
        r#"{"nftables":[
            {"metainfo":{"version":"1.0.9","json_schema_version":1}},
            {"table":{"family":"inet","name":"sanctuary-castle","handle":7}},
            {"chain":{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
              "type":"filter","hook":"output","prio":0,"policy":"drop"}}
        ]}"#
        .to_string()
    }

    /// The v2 identity listing, with each rule's set independently specifiable so
    /// the unequal-set case can be constructed.
    fn v2_identity_listing(denied: &[u32], excepted: &[u32]) -> String {
        let set = |uids: &[u32]| {
            uids.iter()
                .map(|u| u.to_string())
                .collect::<Vec<_>>()
                .join(",")
        };
        let nd_types = KERNEL_ND_ICMPV6_TYPES
            .iter()
            .map(|t| format!("\"{t}\""))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            r#"{{"nftables":[
            {{"metainfo":{{"version":"1.0.9","json_schema_version":1}}}},
            {{"table":{{"family":"inet","name":"sanctuary-castle","handle":7}}}},
            {{"chain":{{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
              "type":"filter","hook":"output","prio":0,"policy":"drop"}}}},
            {{"rule":{{"family":"inet","table":"sanctuary-castle","chain":"output","handle":11,
              "comment":"{identity}",
              "expr":[{{"match":{{"op":"==","left":{{"meta":{{"key":"skuid"}}}},"right":{{"set":[{denied_set}]}}}}}},
                      {{"drop":null}}]}}}},
            {{"rule":{{"family":"inet","table":"sanctuary-castle","chain":"output","handle":12,
              "comment":"{nd}",
              "expr":[{{"match":{{"op":"==","left":{{"payload":{{"protocol":"icmpv6","field":"type"}}}},"right":{{"set":[{nd_types}]}}}}}},
                      {{"accept":null}}]}}}},
            {{"rule":{{"family":"inet","table":"sanctuary-castle","chain":"output","handle":13,
              "comment":"{others}",
              "expr":[{{"match":{{"op":"!=","left":{{"meta":{{"key":"skuid"}}}},"right":{{"set":[{excepted_set}]}}}}}},
                      {{"accept":null}}]}}}}
        ]}}"#,
            identity = NET_RULE_COMMENT_IDENTITY,
            nd = NET_RULE_COMMENT_KERNEL_ND,
            others = NET_RULE_COMMENT_OTHERS,
            denied_set = set(denied),
            excepted_set = set(excepted),
        )
    }

    /// The v2 identity listing in the shape real nft renders it for exactly
    /// ONE denied/excepted uid: a bare scalar `right`, no `{"set": [..]}`
    /// wrapper at all (see `skuid_right_members`'s doc). `v2_identity_listing`
    /// above always emits the array form even for one member, which is the
    /// synthetic shape a fixture composer would reach for and NOT the shape a
    /// single-uid net is actually listed as; this sibling exists so the
    /// recogniser is tested against the real collapse, not just the
    /// convenient one.
    fn v2_identity_listing_single_uid_scalar(denied: &str, excepted: &str) -> String {
        let nd_types = KERNEL_ND_ICMPV6_TYPES
            .iter()
            .map(|t| format!("\"{t}\""))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            r#"{{"nftables":[
            {{"metainfo":{{"version":"1.0.9","json_schema_version":1}}}},
            {{"table":{{"family":"inet","name":"sanctuary-castle","handle":7}}}},
            {{"chain":{{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
              "type":"filter","hook":"output","prio":0,"policy":"drop"}}}},
            {{"rule":{{"family":"inet","table":"sanctuary-castle","chain":"output","handle":11,
              "comment":"{identity}",
              "expr":[{{"match":{{"op":"==","left":{{"meta":{{"key":"skuid"}}}},"right":{denied}}}}},
                      {{"drop":null}}]}}}},
            {{"rule":{{"family":"inet","table":"sanctuary-castle","chain":"output","handle":12,
              "comment":"{nd}",
              "expr":[{{"match":{{"op":"==","left":{{"payload":{{"protocol":"icmpv6","field":"type"}}}},"right":{{"set":[{nd_types}]}}}}}},
                      {{"accept":null}}]}}}},
            {{"rule":{{"family":"inet","table":"sanctuary-castle","chain":"output","handle":13,
              "comment":"{others}",
              "expr":[{{"match":{{"op":"!=","left":{{"meta":{{"key":"skuid"}}}},"right":{excepted}}}}},
                      {{"accept":null}}]}}}}
        ]}}"#,
            identity = NET_RULE_COMMENT_IDENTITY,
            nd = NET_RULE_COMMENT_KERNEL_ND,
            others = NET_RULE_COMMENT_OTHERS,
        )
    }

    /// ITEM 16: the emission floor KEEPS its below-ceiling refusal.
    ///
    /// The three unattestable-uid refusals were added ALONGSIDE this floor, not in place
    /// of it: the ceiling proves a uid is outside the system-daemon band, and the three
    /// refusals prove a uid names one attestable principal. A uid must clear both before
    /// it is sealed into a kernel rule, and this test is what keeps the ceiling half from
    /// being dropped as redundant.
    ///
    /// The emission floor itself is Linux-only, so this asserts the invariant at the
    /// source: the ceiling comparison is present and the three-refusal call does not
    /// replace it.
    #[test]
    fn the_emission_floor_keeps_its_below_ceiling_refusal() {
        let whole = include_str!("nftables.rs");
        let start = whole
            .find("fn validate_agent_binding_input(")
            .expect("the emission floor is in this file");
        let end = whole[start..]
            .find("\n    pub fn load_agent_ruleset_impl(")
            .map(|o| start + o)
            .expect("the floor ends before the ruleset loader");
        let region = &whole[start..end];
        assert!(
            region.contains("binding.agent_uid < binding.system_uid_allow_ceiling"),
            "the below-ceiling refusal must stay at the emission site"
        );
        assert!(
            region.contains("binding.agent_uid < 1"),
            "the root refusal must stay at the emission site"
        );
        // And the three refusals are applied IN ADDITION, after the ceiling check.
        let ceiling_at = region
            .find("binding.agent_uid < binding.system_uid_allow_ceiling")
            .expect("ceiling check");
        let validator_at = region
            .find("validate_safety_net_uid(binding.agent_uid")
            .expect("the three-refusal call is present");
        assert!(
            ceiling_at < validator_at,
            "the ceiling floor runs first and is never replaced by the three refusals"
        );
    }

    #[test]
    fn identity_scope_transaction_text_has_the_three_rules_in_order() {
        let script = build_deny_all_safety_net_script(&identity_scope(&[60124, 60123]));
        let rule_lines: Vec<&str> = script
            .lines()
            .filter(|line| line.starts_with("add rule "))
            .collect();
        assert_eq!(
            rule_lines.len(),
            NET_V2_RULE_COUNT,
            "the identity net is exactly three rules: {script}"
        );
        // ORDER is the invariant: drop the confined identity FIRST, then the
        // kernel's own neighbour discovery, then every other principal.
        assert!(
            rule_lines[0].contains("meta skuid { 60123, 60124 } drop")
                && rule_lines[0].contains(NET_RULE_COMMENT_IDENTITY),
            "rule 1: {}",
            rule_lines[0]
        );
        assert!(
            rule_lines[1].contains(
                "icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } accept"
            ) && rule_lines[1].contains(NET_RULE_COMMENT_KERNEL_ND),
            "rule 2: {}",
            rule_lines[1]
        );
        assert!(
            rule_lines[2].contains("meta skuid != { 60123, 60124 } accept")
                && rule_lines[2].contains(NET_RULE_COMMENT_OTHERS),
            "rule 3: {}",
            rule_lines[2]
        );
        // MLD is not in the carve-out; an accepted MLD report would be a
        // link-local channel an unprivileged multicast join can drive.
        assert!(
            !script.contains("mld"),
            "MLD must not be accepted: {script}"
        );
        // Still one transaction with the add-delete-add fresh table and the drop
        // policy, so no fail-open window exists between teardown and enforcement.
        assert!(script.contains("policy drop"));
        assert!(script.contains("delete table inet sanctuary-castle"));
    }

    #[test]
    fn host_wide_scope_transaction_text_has_no_rules() {
        let script = build_deny_all_safety_net_script(&SafetyNetScope::HostWide);
        assert!(
            !script.contains("add rule "),
            "the host-wide shape is the bare drop policy: {script}"
        );
        assert!(script.contains("policy drop"));
        assert_eq!(SafetyNetScope::HostWide.denied_uids(), Vec::<u32>::new());
        assert_eq!(SafetyNetScope::HostWide.shape_tag(), "v1-host-wide");
        assert_eq!(identity_scope(&[60123]).shape_tag(), "v2-confined-identity");
    }

    #[test]
    fn deny_all_safety_net_recognizer_accepts_both_permanent_shapes() {
        let v1 = v1_host_wide_listing();
        assert!(is_deny_all_safety_net_json(&v1, test_overflow()));
        let v2 = v2_identity_listing(&[60123, 60124], &[60123, 60124]);
        assert!(is_deny_all_safety_net_json(&v2, test_overflow()));
        // Set member order in the listing must not decide recognition.
        let reordered_members = v2_identity_listing(&[60124, 60123], &[60123, 60124]);
        assert!(is_deny_all_safety_net_json(
            &reordered_members,
            test_overflow()
        ));
    }

    /// The confirmed defect's recogniser-side twin: a live table whose ONE
    /// denied uid nft rendered as a bare scalar (the real collapse, not the
    /// convenient array `v2_identity_listing` composes) must still be
    /// recognised as this daemon's OWN deny-all safety net, and
    /// `net_rule_one_uids`/`live_table_uid_bindings` must agree with the
    /// recogniser on the uid it denies. Before `rule_skuid_set_with_verdict`
    /// shared `skuid_right_members` with `net_rule_one_uids`, this scalar
    /// shape refused recognition entirely (`is_deny_all_safety_net_json`
    /// false), which would have let a restart re-arm a net that dropped the
    /// live kernel's already-installed single-uid deny rule.
    #[test]
    fn deny_all_safety_net_recognizer_accepts_a_single_denied_uid_scalar_net() {
        let ov = test_overflow();
        let json = v2_identity_listing_single_uid_scalar("60123", "60123");
        assert!(
            is_deny_all_safety_net_json(&json, ov),
            "a single-uid net in nft's real scalar form must be recognised: {json}"
        );
        assert_eq!(
            net_rule_one_uids(&json),
            vec![60123],
            "the live-binding reader must agree with the recogniser on the same JSON"
        );
        assert_eq!(
            live_table_uid_bindings(&json, &fixture_expectation(), ov),
            LiveTableBindings::Bindings(vec![60123])
        );
    }

    /// The recogniser must still REJECT a scalar-shaped look-alike whose rule 1
    /// and rule 3 name different uids: accepting it would let rule 3 accept a
    /// uid that rule 1 never actually drops (the ordering-invariant this
    /// module documents at `net_v2_rules_match`), and the scalar form must not
    /// get a laxer equality check than the array form already enforces.
    #[test]
    fn deny_all_safety_net_recognizer_rejects_a_single_uid_scalar_mismatch() {
        let ov = test_overflow();
        let mismatched = v2_identity_listing_single_uid_scalar("60123", "60124");
        assert!(
            !is_deny_all_safety_net_json(&mismatched, ov),
            "rule 1 and rule 3 naming different uids must never be recognised as the net"
        );
    }

    /// And a scalar `right` that is not a valid attestable uid at all (root,
    /// the host overflow uid, or a value past `u32`) must be refused exactly
    /// as the array form already is, since the shared extractor must not
    /// bypass the three-refusal revalidation `rule_skuid_set_with_verdict`
    /// applies to every member.
    #[test]
    fn deny_all_safety_net_recognizer_rejects_an_unattestable_scalar_uid() {
        let ov = test_overflow();
        let root = v2_identity_listing_single_uid_scalar("0", "0");
        assert!(
            !is_deny_all_safety_net_json(&root, ov),
            "uid 0 must never be recognised as a live denied identity: {root}"
        );
        let past_u32 = v2_identity_listing_single_uid_scalar("4294967296", "4294967296");
        assert!(
            !is_deny_all_safety_net_json(&past_u32, ov),
            "a value past u32 must never be recognised: {past_u32}"
        );
        // The host overflow uid is the one of the three refusals that depends
        // on the injected `overflow` argument actually reaching
        // `validate_safety_net_uid` through the new shared extractor, rather
        // than on a constant this test would pass even if `overflow` were
        // silently dropped on the scalar path.
        let overflow_uid = TEST_HOST_OVERFLOW_UID.to_string();
        let overflow_net = v2_identity_listing_single_uid_scalar(&overflow_uid, &overflow_uid);
        assert!(
            !is_deny_all_safety_net_json(&overflow_net, ov),
            "the host's own overflow uid must never be recognised: {overflow_net}"
        );
    }

    #[test]
    fn strict_live_net_coverage_matches_the_attempted_scope() {
        let ov = test_overflow();
        let host = SafetyNetScope::HostWide;
        let narrow = identity_scope(&[60123]);
        let wide = identity_scope(&[60123, 60124]);
        let v1 = v1_host_wide_listing();
        let v2 = v2_identity_listing(&[60123, 60124], &[60123, 60124]);
        assert!(deny_all_net_covers_scope_json(&v1, ov, &host));
        assert!(deny_all_net_covers_scope_json(&v1, ov, &wide));
        assert!(deny_all_net_covers_scope_json(&v2, ov, &narrow));
        assert!(deny_all_net_covers_scope_json(&v2, ov, &wide));
        assert!(!deny_all_net_covers_scope_json(&v2, ov, &host));
        assert!(!deny_all_net_covers_scope_json(
            &v2_identity_listing(&[60123], &[60123]),
            ov,
            &wide
        ));
        assert!(!deny_all_net_covers_scope_json(
            &v1.replace("\"policy\":\"drop\"", "\"policy\":\"accept\""),
            ov,
            &host
        ));
    }

    #[test]
    fn deny_all_safety_net_recognizer_refuses_every_near_miss() {
        let v1 = v1_host_wide_listing();
        let v2 = v2_identity_listing(&[60123, 60124], &[60123, 60124]);
        let ov = test_overflow();

        // A `policy accept` base (the owned shape) is NOT the net, in either shape.
        assert!(!is_deny_all_safety_net_json(
            &v1.replace("\"drop\"", "\"accept\""),
            ov
        ));
        assert!(!is_deny_all_safety_net_json(
            &v2.replace("\"policy\":\"drop\"", "\"policy\":\"accept\""),
            ov
        ));
        // A table carrying an owner marker is a captured owned table.
        let owner_marked = v1.replace(
            "\"name\":\"sanctuary-castle\",\"handle\":7",
            "\"name\":\"sanctuary-castle\",\"handle\":7,\"comment\":\"sanctuary-castle-owner:v1:deadbeef\"",
        );
        assert!(!is_deny_all_safety_net_json(&owner_marked, ov));
        // Neither net shape stamps a table comment, so a zero-rule `policy drop`
        // table carrying any table comment is not the net; the disarm recovery
        // arm relies on this refusal (PR-2's matrix case (h) names this fixture).
        let foreign_comment = v1.replace(
            "\"name\":\"sanctuary-castle\",\"handle\":7",
            "\"name\":\"sanctuary-castle\",\"handle\":7,\"comment\":\"someone-elses-drop-table\"",
        );
        assert!(!is_deny_all_safety_net_json(&foreign_comment, ov));
        let v2_foreign_comment = v2.replace(
            "\"name\":\"sanctuary-castle\",\"handle\":7",
            "\"name\":\"sanctuary-castle\",\"handle\":7,\"comment\":\"someone-elses-drop-table\"",
        );
        assert!(!is_deny_all_safety_net_json(&v2_foreign_comment, ov));

        // A REORDERED v2 is a different enforcement outcome (an accept ahead of the
        // drop lets the agent out), so recognition is positional and a swap must be
        // refused rather than normalised. Swapping the two skuid rules' comments
        // puts the `!=` accept in position 1 and the `==` drop in position 3.
        let swapped = v2
            .replace(NET_RULE_COMMENT_IDENTITY, "@@RULE1@@")
            .replace(NET_RULE_COMMENT_OTHERS, NET_RULE_COMMENT_IDENTITY)
            .replace("@@RULE1@@", NET_RULE_COMMENT_OTHERS);
        assert!(!is_deny_all_safety_net_json(&swapped, ov));

        // The ND accept rule MISSING (two rules) is not the three-rule shape.
        let nd_removed: String = v2
            .lines()
            .filter(|line| !line.contains(NET_RULE_COMMENT_KERNEL_ND))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!is_deny_all_safety_net_json(&nd_removed, ov));

        // UNEQUAL sets: rule 3 excepting a uid rule 1 never dropped is the
        // fail-open the ordering exists to prevent.
        assert!(!is_deny_all_safety_net_json(
            &v2_identity_listing(&[60123, 60124], &[60123]),
            ov
        ));
        assert!(!is_deny_all_safety_net_json(
            &v2_identity_listing(&[60123], &[60123, 60124]),
            ov
        ));

        // A FOURTH rule is drift or injection, even a bare accept.
        let with_extra = v2.replace(
            "\n        ]}",
            ",{\"rule\":{\"family\":\"inet\",\"table\":\"sanctuary-castle\",\"chain\":\"output\",\
             \"handle\":14,\"expr\":[{\"accept\":null}]}}\n        ]}",
        );
        assert_ne!(
            with_extra, v2,
            "the fourth-rule fixture must actually differ"
        );
        assert!(!is_deny_all_safety_net_json(&with_extra, ov));

        // A DIFFERENT rule comment on any of the three.
        assert!(!is_deny_all_safety_net_json(
            &v2.replace(
                NET_RULE_COMMENT_IDENTITY,
                "sanctuary-castle-net:v2:something-else"
            ),
            ov
        ));
        assert!(!is_deny_all_safety_net_json(
            &v2.replace(
                NET_RULE_COMMENT_KERNEL_ND,
                "sanctuary-castle-net:v2:something-else"
            ),
            ov
        ));

        // An extra ICMPv6 type in the carve-out (an MLD report) is a channel the
        // agent may drive, so rule 2 is checked for EQUALITY, never containment.
        assert!(!is_deny_all_safety_net_json(
            &v2.replace(
                "\"nd-router-solicit\"",
                "\"nd-router-solicit\",\"mld-listener-report\""
            ),
            ov
        ));

        // A wrong family/name table is not ours, and malformed input is not the net.
        assert!(!is_deny_all_safety_net_json(
            &v1.replace("sanctuary-castle", "sanctuary-castle-test-x"),
            ov
        ));
        assert!(!is_deny_all_safety_net_json("not json", ov));
    }

    #[test]
    fn deny_all_safety_net_recognizer_refuses_sets_the_installer_could_not_have_armed() {
        // The closed installer type cannot place 0, this host's kernel.overflowuid
        // or the invalid sentinel in rule 1, so a well-formed three-rule table
        // carrying one of them was armed by something other than this daemon and
        // must not be recognised (the disarm recovery arm would otherwise delete
        // it as ours).
        let ov = test_overflow();
        for refused in [0u32, TEST_HOST_OVERFLOW_UID, u32::MAX] {
            let listing = v2_identity_listing(&[refused, 60123], &[refused, 60123]);
            assert!(
                !is_deny_all_safety_net_json(&listing, ov),
                "a set carrying {refused} must not be recognised as this daemon's net"
            );
        }
        // A mapped high uid IS attestable and stays recognised.
        assert!(is_deny_all_safety_net_json(
            &v2_identity_listing(&[65535, 100_000], &[65535, 100_000]),
            ov
        ));
    }

    #[test]
    fn castle_table_comment_absence_check_is_independent_of_the_recognizer() {
        let net = r#"{"nftables":[
            {"metainfo":{"version":"1.0.9","json_schema_version":1}},
            {"table":{"family":"inet","name":"sanctuary-castle","handle":7}},
            {"chain":{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
              "type":"filter","hook":"output","prio":0,"policy":"drop"}}
        ]}"#;
        // No comment key at all: absent, as [`is_deny_all_safety_net_json`]
        // also independently requires for this shape.
        assert!(castle_table_comment_is_absent(net));

        // A comment key with ANY content (owner-prefixed or not) is present,
        // regardless of what the recognizer's own owner-marker check answers.
        let owner_commented = net.replace(
            "\"name\":\"sanctuary-castle\",\"handle\":7",
            "\"name\":\"sanctuary-castle\",\"handle\":7,\"comment\":\"sanctuary-castle-owner:v1:deadbeef\"",
        );
        assert!(!castle_table_comment_is_absent(&owner_commented));
        let other_commented = net.replace(
            "\"name\":\"sanctuary-castle\",\"handle\":7",
            "\"name\":\"sanctuary-castle\",\"handle\":7,\"comment\":\"unrelated text\"",
        );
        assert!(!castle_table_comment_is_absent(&other_commented));

        // A missing matching table object, or unparseable JSON, cannot
        // positively prove absence: fail closed (`false`), never `true`.
        assert!(!castle_table_comment_is_absent(
            &net.replace("sanctuary-castle", "sanctuary-castle-test-x")
        ));
        assert!(!castle_table_comment_is_absent("not json"));
    }

    // Off-Linux reachability anchor for `live_castle_table_json`'s stub, the
    // same shape `disarm_is_not_available_off_linux` (runtime_providers.rs)
    // proves for the disarm entry point: there is no nft runtime to read off
    // Linux, so the crate-private inventory fetch reports
    // `NotAvailableOnPlatform` rather than pretending to have read anything.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn live_castle_table_json_is_not_available_off_linux() {
        assert!(matches!(
            live_castle_table_json(),
            Err(NftablesError::NotAvailableOnPlatform)
        ));
    }

    #[test]
    fn owned_identity_refuses_partial_agent_inventory_after_interrupted_mutation() {
        let marker = format!("{OWNER_MARKER_PREFIX}0123456789abcdef0123456789abcdef");
        assert!(parse_owned_table_identity(
            &owned_agent_json(&marker, false, true),
            &fixture_expectation()
        )
        .is_err());
        assert!(parse_owned_table_identity(
            &owned_agent_json(&marker, true, false),
            &fixture_expectation()
        )
        .is_err());
        assert!(parse_owned_table_identity(
            &owned_agent_json(&marker, false, false),
            &fixture_expectation()
        )
        .is_err());
    }

    #[test]
    fn owned_identity_refuses_marker_preserving_expression_mutation() {
        let marker = format!("{OWNER_MARKER_PREFIX}0123456789abcdef0123456789abcdef");
        let mut document: serde_json::Value =
            serde_json::from_str(&owned_agent_json(&marker, true, true)).unwrap();
        let items = document["nftables"].as_array_mut().unwrap();
        let body = items
            .iter_mut()
            .find_map(|item| {
                let rule = item.get_mut("rule")?;
                (rule.get("chain")?.as_str()? != "output").then_some(rule)
            })
            .unwrap();
        // Preserve all ownership comments while replacing the cgroup/mark
        // binding with a match-all queue. Comment-only verification would
        // falsely accept this as the owned runtime.
        body["expr"] = serde_json::json!([{ "queue": { "num": 0 } }]);
        assert!(parse_owned_table_identity(&document.to_string(), &fixture_expectation()).is_err());
    }

    #[test]
    fn owned_identity_requires_both_table_and_chain_handles() {
        let marker = format!("{OWNER_MARKER_PREFIX}0123456789abcdef0123456789abcdef");
        let missing_table_handle = format!(
            r#"{{"nftables":[
              {{"table":{{"family":"inet","name":"sanctuary-castle","comment":"{marker}"}}}},
              {{"chain":{{"family":"inet","table":"sanctuary-castle","name":"output",
                "handle":1,"type":"filter","hook":"output","prio":0,"policy":"accept"}}}}
            ]}}"#
        );
        assert!(parse_owned_table_identity(&missing_table_handle, &fixture_expectation()).is_err());

        let missing_chain_handle = format!(
            r#"{{"nftables":[
              {{"table":{{"family":"inet","name":"sanctuary-castle","handle":2,
                "comment":"{marker}"}}}},
              {{"chain":{{"family":"inet","table":"sanctuary-castle","name":"output",
                "type":"filter","hook":"output","prio":0,"policy":"accept"}}}}
            ]}}"#
        );
        assert!(parse_owned_table_identity(&missing_chain_handle, &fixture_expectation()).is_err());
    }

    #[test]
    fn owned_identity_refuses_injected_rule() {
        // A rule object in the table is the "injected rule" the weaker shape
        // check ignored; the exact-ownership parser must refuse it.
        let marker = format!("{OWNER_MARKER_PREFIX}0123456789abcdef0123456789abcdef");
        let json = format!(
            r#"{{"nftables":[
              {{"table":{{"family":"inet","name":"sanctuary-castle","handle":2,"comment":"{marker}"}}}},
              {{"chain":{{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
                "type":"filter","hook":"output","prio":0,"policy":"accept"}}}},
              {{"rule":{{"family":"inet","table":"sanctuary-castle","chain":"output","handle":9,
                "expr":[{{"accept":null}}]}}}}
            ]}}"#
        );
        assert!(parse_owned_table_identity(&json, &fixture_expectation()).is_err());
    }

    #[test]
    fn owned_identity_refuses_extra_regular_chain() {
        // A second chain (here a regular, hookless chain) is not the pristine L2
        // slice — refuse even though the base output chain is exactly ours.
        let marker = format!("{OWNER_MARKER_PREFIX}0123456789abcdef0123456789abcdef");
        let json = format!(
            r#"{{"nftables":[
              {{"table":{{"family":"inet","name":"sanctuary-castle","handle":2,"comment":"{marker}"}}}},
              {{"chain":{{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
                "type":"filter","hook":"output","prio":0,"policy":"accept"}}}},
              {{"chain":{{"family":"inet","table":"sanctuary-castle","name":"extra","handle":3}}}}
            ]}}"#
        );
        assert!(parse_owned_table_identity(&json, &fixture_expectation()).is_err());
    }

    #[test]
    fn owned_identity_refuses_foreign_set_object() {
        let marker = format!("{OWNER_MARKER_PREFIX}0123456789abcdef0123456789abcdef");
        let json = format!(
            r#"{{"nftables":[
              {{"table":{{"family":"inet","name":"sanctuary-castle","handle":2,"comment":"{marker}"}}}},
              {{"chain":{{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
                "type":"filter","hook":"output","prio":0,"policy":"accept"}}}},
              {{"set":{{"family":"inet","table":"sanctuary-castle","name":"s","handle":4}}}}
            ]}}"#
        );
        assert!(parse_owned_table_identity(&json, &fixture_expectation()).is_err());
    }

    #[test]
    fn owned_identity_refuses_multi_kind_inventory_items() {
        let marker = format!("{OWNER_MARKER_PREFIX}0123456789abcdef0123456789abcdef");
        let mut document: serde_json::Value =
            serde_json::from_str(&owned_json(2, 1, &marker)).unwrap();
        document["nftables"][1]
            .as_object_mut()
            .unwrap()
            .insert("metainfo".to_string(), serde_json::json!({}));
        assert!(parse_owned_table_identity(&document.to_string(), &fixture_expectation()).is_err());
    }

    #[test]
    fn owned_identity_refuses_missing_or_foreign_marker() {
        // No comment at all -> not created by us.
        let no_comment = r#"{"nftables":[
          {"table":{"family":"inet","name":"sanctuary-castle","handle":2}},
          {"chain":{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
            "type":"filter","hook":"output","prio":0,"policy":"accept"}}
        ]}"#;
        assert!(parse_owned_table_identity(no_comment, &fixture_expectation()).is_err());
        // A comment that is not our marker prefix -> foreign.
        let foreign_comment = r#"{"nftables":[
          {"table":{"family":"inet","name":"sanctuary-castle","handle":2,"comment":"someone else"}},
          {"chain":{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
            "type":"filter","hook":"output","prio":0,"policy":"accept"}}
        ]}"#;
        assert!(parse_owned_table_identity(foreign_comment, &fixture_expectation()).is_err());
    }

    #[test]
    fn owned_identity_of_a_same_shape_recreate_differs_by_handle() {
        // The raced/replaced case: a delete+recreate of a same-shaped table gets
        // NEW handles from nft. The parsed identity therefore differs, so a
        // verify against the captured tuple (handle-bound) refuses it. This is
        // what makes "same-shape replacement withdraws readiness" hold.
        let marker = format!("{OWNER_MARKER_PREFIX}0123456789abcdef0123456789abcdef");
        let first =
            parse_owned_table_identity(&owned_json(2, 1, &marker), &fixture_expectation()).unwrap();
        let recreated =
            parse_owned_table_identity(&owned_json(7, 5, &marker), &fixture_expectation()).unwrap();
        assert_ne!(
            first, recreated,
            "a same-shape recreate must not compare equal to the captured identity"
        );
    }

    #[test]
    fn owned_identity_refuses_unparseable_or_empty() {
        assert!(parse_owned_table_identity("", &fixture_expectation()).is_err());
        assert!(parse_owned_table_identity("{}", &fixture_expectation()).is_err());
        assert!(parse_owned_table_identity(r#"{"nftables":[]}"#, &fixture_expectation()).is_err());
    }

    fn make_rule(
        id: &str,
        host: Option<Vec<&str>>,
        port: Option<Vec<u16>>,
        proto: Option<&str>,
        disposition: RuleDisposition,
    ) -> AllowlistRule {
        AllowlistRule {
            id: id.to_string(),
            schema_version: 1,
            created_at: "2026-05-05T00:00:00Z".to_string(),
            description: None,
            match_clause: RuleMatch {
                host: host.map(|v| v.into_iter().map(|s| s.to_string()).collect()),
                host_pattern: None,
                ip: None,
                cidr: None,
                port,
                protocol: proto.map(|s| s.to_string()),
            },
            scope: RuleScope::default(),
            disposition,
            time_window: None,
            derived: None,
        }
    }

    #[test]
    fn agent_chain_name_sanitizes() {
        assert_eq!(agent_chain_name("my-agent"), "agent_my-agent");
        assert_eq!(
            agent_chain_name("agent/with spaces"),
            "agent_agent_x2f_with_x20_spaces"
        );
    }

    #[test]
    fn agent_chain_name_does_not_collapse_colliding_agent_ids() {
        let slash_agent = agent_chain_name("agent/a");
        let underscore_agent = agent_chain_name("agent_a");
        assert_ne!(slash_agent, underscore_agent);
        assert_eq!(slash_agent, "agent_agent_x2f_a");
        assert_eq!(underscore_agent, "agent_agent_a");
    }

    #[test]
    fn agent_chain_name_stays_within_nft_budget() {
        let chain = agent_chain_name(&format!("agent/{}", "x".repeat(400)));
        assert!(chain.len() <= NFT_CHAIN_MAX_LEN);
        assert!(chain.starts_with(AGENT_CHAIN_PREFIX));
    }

    #[test]
    fn build_agent_ruleset_queues_only_the_agent_uid() {
        let frags = vec![NftRuleFragment {
            rule_id: "r1".to_string(),
            nft_expr: "tcp dport 443 accept".to_string(),
        }];
        let script = build_agent_ruleset("test-agent", 4242, &frags);
        assert!(script.contains("flush chain"));
        assert!(!script.contains("tcp dport 443 accept"));
        assert!(script.contains("meta skuid 4242"));
        assert!(script.contains("queue num 0"));
        assert!(script.contains("meta mark set"));
        // No `bypass` flag: an unbound or unreachable NFQUEUE must drop, never
        // release. This is the property the live guarantee actually rests on.
        assert!(!script.contains("bypass"));
        // The retired cgroup match must not reappear anywhere in the emission.
        assert!(!script.contains("cgroupv2"));
        assert!(!script.contains("level "));
    }

    #[test]
    fn build_agent_ruleset_emits_a_bare_integer_uid_never_an_account_name() {
        // The parser accepts only a bare integer (see
        // `parse_skuid_value_accepts_only_a_bare_integer_uid`). Emitting a name
        // here would produce a rule this daemon's own verifier reads as foreign,
        // so the emitter and the parser are pinned to the same form from both
        // sides. Failure mode if this regresses: the wall installs, then the very
        // first health poll declares it foreign and re-arms deny-all.
        let script = build_agent_ruleset("regression", 60123, &[]);
        let skuid_lines: Vec<&str> = script.lines().filter(|l| l.contains("skuid")).collect();
        assert_eq!(
            skuid_lines.len(),
            1,
            "exactly one skuid rule expected: {script}"
        );
        let after = skuid_lines[0]
            .split("meta skuid ")
            .nth(1)
            .expect("expected 'meta skuid ' marker");
        assert!(
            after.starts_with("60123 "),
            "uid must be emitted as a bare decimal integer, got: {after}"
        );
        assert!(
            !after.starts_with('"'),
            "a quoted/name form is never emitted"
        );
    }

    #[test]
    fn build_agent_ruleset_registers_mark_for_nfqueue_attribution() {
        let script = build_agent_ruleset("attributed-agent", 4242, &[]);
        let mark = crate::nfqueue::agent_mark("attributed-agent");
        assert!(
            script.contains(&format!("meta mark set 0x{mark:08x} queue num 0")),
            "catchall must set a per-agent mark before NFQUEUE: {script}"
        );
        assert_eq!(
            crate::nfqueue::resolve_agent_mark(mark),
            Some("attributed-agent".to_string())
        );
    }

    #[test]
    fn rule_to_nft_expr_allow_with_host_and_port_stays_on_nfqueue() {
        let r = make_rule(
            "r1",
            Some(vec!["api.anthropic.com"]),
            Some(vec![443]),
            Some("tcp"),
            RuleDisposition::Allow,
        );
        let frags = rule_to_nft_expr(&r);
        assert!(
            frags.is_empty(),
            "host allow rules must not become static port-wide nft accepts"
        );
    }

    #[test]
    fn rule_to_nft_expr_deny_no_host_stays_ordered_on_nfqueue() {
        let r = make_rule(
            "r2",
            None,
            Some(vec![80, 8080]),
            Some("tcp"),
            RuleDisposition::Deny,
        );
        let frags = rule_to_nft_expr(&r);
        assert!(frags.is_empty());
    }

    #[test]
    fn rule_to_nft_expr_prompt_produces_no_fragments() {
        let r = make_rule(
            "r3",
            Some(vec!["example.com"]),
            None,
            None,
            RuleDisposition::Prompt,
        );
        let frags = rule_to_nft_expr(&r);
        assert!(frags.is_empty());
    }

    #[test]
    fn rule_to_nft_expr_multiple_hosts_stays_on_nfqueue() {
        let r = make_rule(
            "r4",
            Some(vec!["a.com", "b.com"]),
            Some(vec![443]),
            Some("tcp"),
            RuleDisposition::Allow,
        );
        let frags = rule_to_nft_expr(&r);
        assert!(
            frags.is_empty(),
            "multi-host rules must not emit comment-only static verdicts"
        );
    }

    #[test]
    fn rule_to_nft_expr_host_pattern_stays_on_nfqueue() {
        let mut r = make_rule(
            "r5",
            None,
            Some(vec![443]),
            Some("tcp"),
            RuleDisposition::Deny,
        );
        r.match_clause.host_pattern = Some(".example.com".to_string());
        let frags = rule_to_nft_expr(&r);
        assert!(
            frags.is_empty(),
            "host-pattern rules must not become static port-wide nft drops"
        );
    }

    #[test]
    fn rule_to_nft_expr_ip_axis_stays_on_nfqueue() {
        // An ip-pinned rule (the genuine reserved local distress shape) must
        // NOT lower to a bare `tcp dport 8741 accept` that would grant the port
        // to ANY destination — the loopback constraint would be lost in the
        // kernel (codex round-3). It stays on the evaluator path.
        let mut r = make_rule(
            "r-ip",
            None,
            Some(vec![8741]),
            Some("tcp"),
            RuleDisposition::Allow,
        );
        r.match_clause.ip = Some(vec!["127.0.0.1".to_string(), "::1".to_string()]);
        let frags = rule_to_nft_expr(&r);
        assert!(
            frags.is_empty(),
            "ip-pinned rules must not become static port-wide nft accepts"
        );
    }

    #[test]
    fn rule_to_nft_expr_cidr_axis_stays_on_nfqueue() {
        let mut r = make_rule(
            "r-cidr",
            None,
            Some(vec![8741]),
            Some("tcp"),
            RuleDisposition::Deny,
        );
        r.match_clause.cidr = Some(vec!["10.0.0.0/8".to_string()]);
        let frags = rule_to_nft_expr(&r);
        assert!(
            frags.is_empty(),
            "cidr rules must not become static port-wide nft drops"
        );
    }

    // ---- build_agent_jump_rule pure-helper tests --------------------------

    #[test]
    fn build_agent_jump_rule_emits_canonical_shape() {
        // Pin the exact rule string. This is what the base output chain needs to
        // route the agent's uid-owned packets into the per-agent chain.
        let rule = build_agent_jump_rule("alpha", 4242);
        assert_eq!(
            rule,
            "add rule inet sanctuary-castle output meta skuid 4242 goto agent_alpha"
        );
    }

    #[test]
    fn build_agent_jump_rule_uses_goto_not_jump() {
        // INVARIANT: `goto` is terminating; `jump` returns to the accept-policy
        // base chain and would silently undo the per-agent verdict. The parse
        // side pins the same verb (`validate_owned_jump_expr`), so a regression
        // on either side is caught by the other.
        let rule = build_agent_jump_rule("alpha", 4242);
        assert!(rule.contains(" goto agent_alpha"));
        assert!(!rule.contains(" jump "));
    }

    #[test]
    fn build_agent_jump_rule_chain_name_matches_agent_chain_name() {
        // The goto target must match agent_chain_name(agent_id) exactly so
        // the per-agent chain created by load_agent_ruleset_impl is the
        // chain reached by this jump.
        for agent_id in &["alpha", "my-agent", "team_a.svc1", "weird/id"] {
            let rule = build_agent_jump_rule(agent_id, 4242);
            let chain = agent_chain_name(agent_id);
            assert!(
                rule.ends_with(&format!("goto {chain}")),
                "jump rule must end with goto <chain_name> matching agent_chain_name; \
                 agent={agent_id} chain={chain} rule={rule}"
            );
        }
    }

    #[test]
    fn body_and_jump_emit_the_same_uid_the_parser_requires_them_to_agree_on() {
        // Cross-emitter agreement, pinned at the source: `parse_owned_table_inventory`
        // refuses a body and jump that disagree on the uid, so the two emitters
        // must derive their match from the same value. A drift here would install
        // a wall that fails its own next health poll.
        let body = build_agent_ruleset("agreed", 4242, &[]);
        let jump = build_agent_jump_rule("agreed", 4242);
        assert!(body.contains("meta skuid 4242"));
        assert!(jump.contains("meta skuid 4242"));
    }

    #[test]
    fn build_agent_fail_closed_ruleset_drops_everything_in_chain() {
        let script = build_agent_fail_closed_ruleset("refresh-agent");
        assert!(script.contains("flush chain inet sanctuary-castle agent_refresh-agent"));
        assert!(script.contains("add rule inet sanctuary-castle agent_refresh-agent drop"));
        assert!(
            !script.contains("queue"),
            "refresh fail-closed stage must drop rather than queue: {script}"
        );
    }

    // ---- parse_jump_rule_handles tests ------------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_jump_rule_handles_matches_target_chain_only() {
        // Synthetic `nft -a list chain` output with three rules: one
        // jumping to our chain, one jumping to a different chain, one
        // doing something else entirely.
        //
        // The jump lines carry the PRODUCTION `meta skuid <uid>` match this
        // emitter now builds (`build_agent_jump_rule`); a fixture still depicting
        // the retired `socket cgroupv2` match would keep testing the parser
        // against a listing the kernel can no longer produce.
        let listing = "\
table inet sanctuary-castle {
\tchain output {
\t\ttype filter hook output priority 0; policy accept;
\t\tmeta skuid 4242 goto agent_alpha # handle 5
\t\tmeta skuid 4243 goto agent_beta # handle 7
\t\tudp dport 53 accept # handle 9
\t}
}";
        let handles = linux::parse_jump_rule_handles(listing, "agent_alpha");
        assert_eq!(handles, vec![5]);
        let handles_beta = linux::parse_jump_rule_handles(listing, "agent_beta");
        assert_eq!(handles_beta, vec![7]);
        let handles_missing = linux::parse_jump_rule_handles(listing, "agent_gamma");
        assert!(handles_missing.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_jump_rule_handles_does_not_substring_match() {
        // Critical correctness invariant: chain names that share a prefix
        // (`agent_foo` and `agent_foo_bar`) must not collide. A naive
        // substring match for `agent_foo` would wrongly hit the line
        // ending in `goto agent_foo_bar`.
        let listing = "\
\t\tmeta skuid 4242 goto agent_foo # handle 11
\t\tmeta skuid 4243 goto agent_foo_bar # handle 13
";
        let handles_foo = linux::parse_jump_rule_handles(listing, "agent_foo");
        assert_eq!(handles_foo, vec![11], "must not match agent_foo_bar");
        let handles_foo_bar = linux::parse_jump_rule_handles(listing, "agent_foo_bar");
        assert_eq!(handles_foo_bar, vec![13]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_jump_rule_handles_collects_all_duplicates() {
        // If a prior install-and-no-remove path leaked stale jumps for the
        // same agent (the bug shape `install_agent_jump_rule_impl`'s
        // delete-then-add prevents going forward), the parser must surface
        // every handle so a remove call cleans them all out.
        let listing = "\
\t\tmeta skuid 4242 goto agent_dup # handle 21
\t\tmeta skuid 4242 goto agent_dup # handle 22
\t\tmeta skuid 4242 goto agent_dup # handle 23
";
        let handles = linux::parse_jump_rule_handles(listing, "agent_dup");
        assert_eq!(handles, vec![21, 22, 23]);
    }
}
