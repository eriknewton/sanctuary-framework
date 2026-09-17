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
    /// The CURRENT policy snapshot confines `agent_uid` under `fortress_id`.
    /// Every live per-agent binding must carry exactly this uid AND a seal that
    /// recomputes under this fortress id. This is the trusted expectation the
    /// design names, and it is read fresh at each comparison, never frozen at
    /// acquisition: a manifest reload that changes the uid must invalidate a
    /// stale kernel binding rather than keep blessing it.
    Confined { fortress_id: String, agent_uid: u32 },
    /// The current snapshot confines NO agent uid (absent `agent_origin`, or a
    /// non-`uid` mode), or the table was just created and cannot yet hold one.
    /// Any live per-agent binding is then unverifiable against a trusted
    /// expectation, so it reads foreign — absent evidence is not passing
    /// evidence.
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
    pub fn install_deny_all_safety_net_impl() -> Result<(), NftablesError> {
        let castle_table = castle_table();
        // add (ensure exists) -> delete (drop any drifted/leftover contents of
        // OUR named table) -> add (fresh empty) -> base output chain, policy DROP.
        let script = format!(
            "add table {CASTLE_FAMILY} {castle_table}\n\
             delete table {CASTLE_FAMILY} {castle_table}\n\
             add table {CASTLE_FAMILY} {castle_table}\n\
             add chain {CASTLE_FAMILY} {castle_table} output \
             {{ type filter hook output priority 0 ; policy drop ; }}\n"
        );
        run_nft_stdin(&script).map_err(|err| {
            NftablesError::InvocationFailed(format!(
                "failed to install the GF1 deny-all safety net (kernel egress \
                 state for the owned scopes may be indeterminate): {err}"
            ))
        })
    }

    /// GF1.1: whether the LIVE `sanctuary-castle` table is exactly this daemon's
    /// deny-all safety net (see [`super::is_deny_all_safety_net_json`]). Absence
    /// or an nft error reads as "not the net" (false / propagated error), so a
    /// caller only ever recovers on a positively-recognized fail-closed net.
    pub fn live_table_is_deny_all_safety_net_impl() -> Result<bool, NftablesError> {
        match run_nft(&["-j", "list", "table", CASTLE_FAMILY, castle_table()]) {
            Ok(json) => Ok(super::is_deny_all_safety_net_json(&json)),
            Err(NftablesError::InvocationFailed(msg))
                if msg.contains("No such file or directory") || msg.contains("does not exist") =>
            {
                Ok(false)
            }
            Err(e) => Err(e),
        }
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
    pub fn verify_owned_castle_table_impl(
        ownership: &CastleTableOwnership,
        expectation: &super::ExpectedAgentBinding,
    ) -> Result<Vec<String>, NftablesError> {
        let json = run_nft(&["-a", "-j", "list", "table", CASTLE_FAMILY, castle_table()])?;
        let live = super::parse_owned_table_inventory(&json, expectation)?;
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

/// GF1.1: whether an `nft -j list table inet sanctuary-castle` JSON document is
/// EXACTLY this daemon's deny-all safety net (`install_deny_all_safety_net_impl`
/// output): one `inet/sanctuary-castle` table with NO owner marker comment, one
/// base `output` chain (`type filter hook output priority 0`, `policy DROP`), and
/// NOTHING else -- zero rules, zero agent chains, zero sets/maps.
///
/// This is the recognizer for the create-failure recovery state. When the
/// authenticated journal is `Preparing` for THIS boot but `capture` fails, the
/// live table being this exact fail-CLOSED net (never any shape the owned path
/// emits, which is always `policy accept`) is what distinguishes "our own
/// half-finished acquisition that ReArmLostOwned armed" from a foreign table.
/// Combined with the authenticated Preparing-this-boot journal at the call site,
/// it is the "this boot + source" proof that the daemon created this net, so
/// recovery may reset/clear it. Residual (a foreign actor swapping in an
/// identical-shape `policy drop` net in the window) is the inherent CAP_NET_ADMIN
/// bound documented on `install_deny_all_safety_net_impl` (GF1.4), and is
/// fail-CLOSED either way.
///
/// Pure and cross-platform so the recognizer is unit-testable without a kernel.
pub fn is_deny_all_safety_net_json(json: &str) -> bool {
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(json) else {
        return false;
    };
    let Some(items) = doc.get("nftables").and_then(|v| v.as_array()) else {
        return false;
    };
    let mut saw_table = false;
    let mut saw_drop_base_chain = false;
    for item in items {
        let Some(obj) = item.as_object() else {
            return false;
        };
        if obj.len() != 1 {
            return false;
        }
        for (kind, val) in obj {
            match kind.as_str() {
                "metainfo" => {}
                "table" => {
                    if saw_table {
                        return false; // more than one table object
                    }
                    let ours = val.get("family").and_then(|v| v.as_str()) == Some(CASTLE_FAMILY)
                        && val.get("name").and_then(|v| v.as_str()) == Some(castle_table());
                    // The net is UNMARKED by construction; an owner marker here
                    // means this is NOT the bare safety net (it would be a captured
                    // owned table, handled by the normal parser instead).
                    let has_owner_marker = val
                        .get("comment")
                        .and_then(|v| v.as_str())
                        .is_some_and(|c| c.starts_with(OWNER_MARKER_PREFIX));
                    if !ours || has_owner_marker {
                        return false;
                    }
                    saw_table = true;
                }
                "chain" => {
                    if saw_drop_base_chain {
                        return false; // more than one chain
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
                        return false;
                    }
                    saw_drop_base_chain = true;
                }
                // A rule, agent chain, set, map, flowtable, or any other object
                // means this is NOT the bare deny-all net.
                _ => return false,
            }
        }
    }
    saw_table && saw_drop_base_chain
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
}

/// Parse an owned-table inventory and check it against `expectation`.
///
/// `expectation` is the whole security content of the agent-binding half of this
/// parse: shape, seal, body/jump agreement and cardinality all prove the
/// inventory is INTERNALLY consistent, which an actor that rewrote both
/// expressions and both comments can also achieve. Only
/// [`ExpectedAgentBinding::Confined`] compares the live uid against a value this
/// process did not read out of the kernel.
fn parse_owned_table_inventory(
    json: &str,
    expectation: &ExpectedAgentBinding,
) -> Result<ParsedOwnedTableInventory, NftablesError> {
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
                if expr_uid != *agent_uid {
                    return Err(NftablesError::ForeignState(format!(
                        "agent {agent_id:?} skuid match {expr_uid} is not the uid the current \
                         signed manifest confines ({agent_uid}); a live binding that routes \
                         a different uid is refused fail-closed"
                    )));
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
    Ok(ParsedOwnedTableInventory {
        ownership: CastleTableOwnership {
            table_handle,
            base_chain_handle,
            marker,
        },
        agent_ids,
    })
}

/// Pure parser used by health and ownership checks. Parsing untrusted inventory
/// must never mutate the process-global packet-attribution registry.
pub fn parse_owned_table_identity(
    json: &str,
    expectation: &ExpectedAgentBinding,
) -> Result<CastleTableOwnership, NftablesError> {
    parse_owned_table_inventory(json, expectation).map(|parsed| parsed.ownership)
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
pub fn install_deny_all_safety_net() -> Result<(), NftablesError> {
    linux::install_deny_all_safety_net_impl()
}

#[cfg(not(target_os = "linux"))]
pub fn install_deny_all_safety_net() -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// GF1.1: whether the LIVE table is exactly this daemon's deny-all safety net.
/// See [`linux::live_table_is_deny_all_safety_net_impl`].
#[cfg(target_os = "linux")]
pub fn live_table_is_deny_all_safety_net() -> Result<bool, NftablesError> {
    linux::live_table_is_deny_all_safety_net_impl()
}

#[cfg(not(target_os = "linux"))]
pub fn live_table_is_deny_all_safety_net() -> Result<bool, NftablesError> {
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
#[cfg(target_os = "linux")]
pub fn load_agent_ruleset(
    id: &AgentRulesetId,
    ruleset: &str,
    binding: AgentUidBinding,
) -> Result<(), NftablesError> {
    linux::load_agent_ruleset_impl(id, ruleset, binding)
}

#[cfg(not(target_os = "linux"))]
pub fn load_agent_ruleset(
    _id: &AgentRulesetId,
    _ruleset: &str,
    _binding: AgentUidBinding,
) -> Result<(), NftablesError> {
    Err(NftablesError::NotAvailableOnPlatform)
}

/// Replace an agent ruleset with a fail-closed drop chain and atomically wire
/// the uid jump to that chain. Used to park an agent at deny while its binding
/// is replaced, so no window exists in which its packets reach `policy accept`.
#[cfg(target_os = "linux")]
pub fn load_agent_fail_closed_ruleset(
    id: &AgentRulesetId,
    binding: AgentUidBinding,
) -> Result<(), NftablesError> {
    linux::load_agent_fail_closed_ruleset_impl(id, binding)
}

#[cfg(not(target_os = "linux"))]
pub fn load_agent_fail_closed_ruleset(
    _id: &AgentRulesetId,
    _binding: AgentUidBinding,
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

    #[test]
    fn ordinary_inventory_parsing_is_pure_and_reclaim_metadata_is_complete() {
        let marker = fixture_marker();
        let mark = crate::nfqueue::agent_mark("agent-one");
        let before = crate::nfqueue::resolve_agent_mark(mark);
        let parsed = parse_owned_table_inventory(
            &owned_agent_json(&marker, true, true),
            &fixture_expectation(),
        )
        .expect("complete inventory");
        assert_eq!(parsed.agent_ids, vec!["agent-one".to_string()]);
        assert_eq!(
            crate::nfqueue::resolve_agent_mark(mark),
            before,
            "health/parser calls must not mutate global NFQUEUE attribution; only the \
             serialized authenticated reclaim path may restore these IDs"
        );
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

    #[test]
    fn deny_all_safety_net_recognizer_accepts_only_the_bare_drop_net() {
        // The exact shape `install_deny_all_safety_net_impl` produces: one unmarked
        // inet/sanctuary-castle table + one base output chain, policy DROP, nothing
        // else. This is the GF1.1 create-failure recovery recognizer.
        let net = r#"{"nftables":[
            {"metainfo":{"version":"1.0.9","json_schema_version":1}},
            {"table":{"family":"inet","name":"sanctuary-castle","handle":7}},
            {"chain":{"family":"inet","table":"sanctuary-castle","name":"output","handle":1,
              "type":"filter","hook":"output","prio":0,"policy":"drop"}}
        ]}"#;
        assert!(is_deny_all_safety_net_json(net));

        // A `policy accept` base (the owned shape) is NOT the deny-all net.
        assert!(!is_deny_all_safety_net_json(
            &net.replace("\"drop\"", "\"accept\"")
        ));
        // A table carrying an owner marker is a captured owned table, not the net.
        let marked = net.replace(
            "\"name\":\"sanctuary-castle\",\"handle\":7",
            "\"name\":\"sanctuary-castle\",\"handle\":7,\"comment\":\"sanctuary-castle-owner:v1:deadbeef\"",
        );
        assert!(!is_deny_all_safety_net_json(&marked));
        // Any extra rule means it is not the BARE net.
        let with_rule = net.replace(
            "\"policy\":\"drop\"}}",
            "\"policy\":\"drop\"}},{\"rule\":{\"family\":\"inet\",\"table\":\"sanctuary-castle\",\"chain\":\"output\",\"handle\":9,\"expr\":[{\"accept\":null}]}}",
        );
        assert!(!is_deny_all_safety_net_json(&with_rule));
        // A wrong family/name table is not ours.
        assert!(!is_deny_all_safety_net_json(
            &net.replace("sanctuary-castle", "sanctuary-castle-test-x")
        ));
        assert!(!is_deny_all_safety_net_json("not json"));
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
