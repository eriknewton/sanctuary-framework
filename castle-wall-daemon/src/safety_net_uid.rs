//! The shared validator for every uid the Linux safety net will name in a kernel
//! rule, and the CLOSED types that carry those uids to the installer.
//!
//! Design: `Review/Sanctuary/Linux_Safety_Net_Carveout_Design_2026-09-17.md`
//! (D1, D1b, D1c). The net denies exactly the confined identity by matching the
//! uid the kernel recorded on the sending socket (`meta skuid`), so the VALUES in
//! that match decide who keeps egress. Three values are not attestable identities
//! and must never reach rule 1:
//!
//!   * `0` is root, which is the operator, never a confined agent;
//!   * the host's configured `kernel.overflowuid` is what `from_kuid_munged`
//!     renders for EVERY credential the current namespace cannot map, so denying
//!     it denies an unbounded, unknown set of principals rather than one identity;
//!   * `u32::MAX` is the invalid-uid sentinel and names no principal at all.
//!
//! The refusal is a TYPE, not a convention. [`ValidatedSafetyNetUid`] and
//! [`ConfinedUidSet`] both have private fields and no constructor outside this
//! module, so a caller elsewhere in the crate cannot place a raw `u32` into the
//! net's rule 1 even by mistake: it must come through
//! [`validate_safety_net_uid`]. `safety_net_scope_is_closed_to_raw_uids` in the
//! tests below is the privacy proof.
//!
//! The ceiling is a SEPARATE and still-live bound: admission
//! (`crate::policy::confined_agent_uid_from_loaded_manifest`) and the emission
//! floor (`crate::nftables::linux::validate_agent_binding_input`) keep their
//! `uid < system_uid_allow_ceiling` refusal and mint through this module in
//! ADDITION to it. These three refusals never replace that ceiling. The set type
//! itself carries no ceiling, because a uid recovered from a live kernel table or
//! from an earlier journal record may predate the current manifest's ceiling, and
//! a mapped high uid (65535, 100000) is a perfectly attestable identity.

use std::path::{Path, PathBuf};

/// The sysctl whose value the kernel substitutes for any credential the reading
/// namespace cannot map. MUST be the `kernel.` one: `/proc/sys/fs/overflowuid` is
/// a separate legacy-filesystem setting that a host can configure differently,
/// and reading it instead would let an unmappable credential through.
/// Must match the path named in `D1c` of the design memo and in
/// `server/src/castle-wall/allowlist/agent-origin.ts` (which documents this
/// host-specific read as the one producer/consumer asymmetry).
pub const OVERFLOW_UID_SYSCTL_PATH: &str = "/proc/sys/kernel/overflowuid";

/// The invalid-uid sentinel. Named rather than written as a literal so the
/// refusal reads as "the sentinel", not as "some large number".
pub const INVALID_UID_SENTINEL: u32 = u32::MAX;

/// Longest plausible `kernel.overflowuid` text: ten decimal digits (the widest
/// `u32`, 4294967295) plus one trailing newline, plus one byte of slack so an
/// over-long file is READ as over-long and refused rather than silently cut.
const MAX_OVERFLOW_UID_FILE_BYTES: usize = 10 + 1 + 1;

/// Why a uid may not be named in the safety net's rules.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SafetyNetUidError {
    /// uid 0. The operator is exactly who the net must never deny.
    #[error("uid 0 is root and is never a confined agent; the safety net would deny the operator")]
    Root,
    /// The host's configured overflow uid: an unbounded set of unmapped
    /// credentials render as this one value, so it identifies no single principal.
    #[error(
        "uid {uid} is this host's configured kernel.overflowuid, which every unmappable \
         credential renders as; it names no single principal and cannot be confined"
    )]
    HostOverflowUid { uid: u32 },
    /// The invalid-uid sentinel.
    #[error("uid {INVALID_UID_SENTINEL} is the invalid-uid sentinel and names no principal")]
    InvalidSentinel,
    /// A deny set with no members would install a rule matching nothing while
    /// claiming to confine an identity.
    #[error("a confined uid set may never be empty; the host-wide scope is the explicit shape")]
    EmptySet,
    /// The overflow sysctl could not be read or parsed. FAIL CLOSED: an unknown
    /// collision value is never turned into an admission.
    #[error(
        "could not read a usable kernel.overflowuid at {path}: {reason}; \
         no uid can be admitted without it"
    )]
    OverflowUidUnreadable { path: PathBuf, reason: String },
}

/// The host's configured `kernel.overflowuid`, read once and carried as a type so
/// a caller cannot pass an arbitrary number where the host's own value belongs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostOverflowUid(u32);

impl HostOverflowUid {
    /// Read the running host's value from [`OVERFLOW_UID_SYSCTL_PATH`].
    ///
    /// FAILURE MODE, for the operator reading a refusal: on a container or an
    /// image without that sysctl this returns
    /// [`SafetyNetUidError::OverflowUidUnreadable`] and NO uid-mode manifest is
    /// admitted. That is deliberate, and it looks like a manifest that "used to
    /// load" refusing after a host change; the net for such a host comes from the
    /// journal and the live table instead.
    pub fn from_host() -> Result<Self, SafetyNetUidError> {
        Self::read_at(Path::new(OVERFLOW_UID_SYSCTL_PATH))
    }

    /// Read and parse the value from `path`. Pure over the path so the missing,
    /// empty, non-numeric and trailing-newline cases are all testable without
    /// touching the host's sysctls.
    pub fn read_at(path: &Path) -> Result<Self, SafetyNetUidError> {
        let unreadable = |reason: String| SafetyNetUidError::OverflowUidUnreadable {
            path: path.to_path_buf(),
            reason,
        };
        let raw =
            std::fs::read_to_string(path).map_err(|e| unreadable(format!("read failed: {e}")))?;
        // INVARIANT: procfs text, not a number on the wire. The value arrives with
        // a trailing newline, so trim BEFORE parsing; an untrimmed parse fails and
        // would fail closed on a perfectly healthy host.
        if raw.len() > MAX_OVERFLOW_UID_FILE_BYTES {
            return Err(unreadable(format!(
                "file is {} bytes, over the {MAX_OVERFLOW_UID_FILE_BYTES}-byte bound for a \
                 decimal u32 and a newline",
                raw.len()
            )));
        }
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(unreadable("file is empty".to_string()));
        }
        let value: u32 = trimmed
            .parse()
            .map_err(|e| unreadable(format!("value {trimmed:?} is not a u32: {e}")))?;
        Ok(Self(value))
    }

    /// Construct from a known value. Test-only ON PURPOSE.
    ///
    /// The type exists so a caller cannot pass an arbitrary number where the HOST's own
    /// configured value belongs. A public raw constructor would defeat that: any caller
    /// could mint an overflow uid of its choosing and the three-refusal function would
    /// then refuse the wrong value while admitting the real credential-collision one.
    /// Production has exactly two mints, both readers: [`Self::from_host`] and
    /// [`Self::read_at`]. `the_overflow_type_has_no_production_raw_constructor` states
    /// the property.
    #[cfg(test)]
    pub(crate) fn from_value(value: u32) -> Self {
        Self(value)
    }

    /// The configured value.
    pub fn value(self) -> u32 {
        self.0
    }
}

/// A uid that has passed the three refusals and may therefore appear in the
/// safety net's `meta skuid` sets.
///
/// The field is PRIVATE and this module exposes no other constructor, so the only
/// way to obtain one is [`validate_safety_net_uid`]. That is what makes
/// `crate::nftables::SafetyNetScope::Identity` closed: rule 1 cannot name `0`,
/// the host overflow uid or the sentinel from anywhere in the crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ValidatedSafetyNetUid(u32);

impl ValidatedSafetyNetUid {
    /// The validated numeric value, for rendering into a kernel rule.
    pub fn value(self) -> u32 {
        self.0
    }
}

/// Apply the three refusals and mint the typed value.
///
/// Returns the typed uid rather than `Result<(), _>` on purpose: a validator that
/// returns unit can be called and its result dropped while the raw value travels
/// on, which is the shape that let an unattestable number reach a rule. Here the
/// only path to the value is through the check.
///
/// INVARIANT: this function applies NO ceiling. The ceiling belongs to admission
/// and to the emission floor, which apply it IN ADDITION to this call; a uid
/// recovered from the live table or from an earlier journal record legitimately
/// predates the current manifest's ceiling, and refusing it here would silently
/// drop a still-live confined identity out of the deny set.
pub fn validate_safety_net_uid(
    uid: u32,
    overflow: HostOverflowUid,
) -> Result<ValidatedSafetyNetUid, SafetyNetUidError> {
    if uid == 0 {
        return Err(SafetyNetUidError::Root);
    }
    if uid == INVALID_UID_SENTINEL {
        return Err(SafetyNetUidError::InvalidSentinel);
    }
    if uid == overflow.value() {
        return Err(SafetyNetUidError::HostOverflowUid { uid });
    }
    Ok(ValidatedSafetyNetUid(uid))
}

/// The non-empty set of validated uids the net's rule 1 denies and rule 3
/// excepts.
///
/// Opaque by construction: a private field, no `Default`, no empty constructor,
/// no raw-`u32` constructor and no public collection constructor. The single
/// constructor is [`ConfinedUidSet::from_validated`], in this module, and it
/// refuses an empty collection, so `SafetyNetScope::Identity` can never carry a
/// set that matches nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfinedUidSet(Vec<ValidatedSafetyNetUid>);

impl ConfinedUidSet {
    /// Build the set from validated uids, sorted and deduplicated.
    ///
    /// INVARIANT: never empty. An empty `Identity` scope would render
    /// `meta skuid { } drop`, which nft refuses, and a caller that meant "no
    /// identity is recoverable" must say so with the host-wide scope and its own
    /// audited reason, never with an empty identity set.
    ///
    /// Sorted and deduplicated so the rendered rule text and the JSON the
    /// recogniser reads back are STABLE for the same set whatever order the three
    /// sources contributed in; an unstable order would make the recogniser's
    /// set-equality check depend on discovery order.
    pub fn from_validated(
        uids: impl IntoIterator<Item = ValidatedSafetyNetUid>,
    ) -> Result<Self, SafetyNetUidError> {
        let mut values: Vec<ValidatedSafetyNetUid> = uids.into_iter().collect();
        values.sort_unstable();
        values.dedup();
        if values.is_empty() {
            return Err(SafetyNetUidError::EmptySet);
        }
        Ok(Self(values))
    }

    /// The validated uids, ascending and deduplicated.
    pub fn uids(&self) -> Vec<u32> {
        self.0.iter().map(|u| u.value()).collect()
    }

    /// How many distinct uids the net denies. Non-zero by construction.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always false. Present because clippy asks any type with `len` for it, and
    /// answering `false` in one place is better than a per-call-site `#[allow]`.
    pub fn is_empty(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A host whose overflow uid is the common default, so the fixture reads like
    /// a real box rather than a number chosen to make a test pass.
    const FIXTURE_OVERFLOW_UID: u32 = 65534;

    fn fixture_host() -> HostOverflowUid {
        HostOverflowUid::from_value(FIXTURE_OVERFLOW_UID)
    }

    #[test]
    fn three_refusals_reject_root_the_host_overflow_uid_and_the_sentinel() {
        assert_eq!(
            validate_safety_net_uid(0, fixture_host()),
            Err(SafetyNetUidError::Root)
        );
        assert_eq!(
            validate_safety_net_uid(FIXTURE_OVERFLOW_UID, fixture_host()),
            Err(SafetyNetUidError::HostOverflowUid {
                uid: FIXTURE_OVERFLOW_UID
            })
        );
        assert_eq!(
            validate_safety_net_uid(INVALID_UID_SENTINEL, fixture_host()),
            Err(SafetyNetUidError::InvalidSentinel)
        );
    }

    #[test]
    fn mapped_high_uids_are_attestable_and_admitted() {
        // D1c: the set type carries no ceiling and no 65534 constant. A mapped
        // 65535 or 100000 is a real, attestable identity.
        for uid in [1u32, 1000, 65533, 65535, 100_000] {
            assert_eq!(
                validate_safety_net_uid(uid, fixture_host())
                    .expect("mapped uid is admitted")
                    .value(),
                uid
            );
        }
    }

    #[test]
    fn the_refused_overflow_uid_is_the_hosts_own_value_never_a_constant() {
        // A host configured with kernel.overflowuid=65533 keeps a mapped 65534
        // admitted. This is why the daemon never hard-codes 65534.
        let host = HostOverflowUid::from_value(65533);
        assert_eq!(
            validate_safety_net_uid(65533, host),
            Err(SafetyNetUidError::HostOverflowUid { uid: 65533 })
        );
        assert_eq!(
            validate_safety_net_uid(65534, host)
                .expect("a mapped 65534 is admitted on this host")
                .value(),
            65534
        );
    }

    #[test]
    fn overflow_uid_reads_trimmed_procfs_text_and_fails_closed_otherwise() {
        let dir = tempfile::tempdir().expect("tempdir");
        let good = dir.path().join("overflowuid");
        std::fs::write(&good, "65534\n").expect("write");
        assert_eq!(
            HostOverflowUid::read_at(&good)
                .expect("trailing newline is trimmed")
                .value(),
            65534
        );

        let empty = dir.path().join("empty");
        std::fs::write(&empty, "").expect("write");
        assert!(matches!(
            HostOverflowUid::read_at(&empty),
            Err(SafetyNetUidError::OverflowUidUnreadable { .. })
        ));

        let garbage = dir.path().join("garbage");
        std::fs::write(&garbage, "not-a-number\n").expect("write");
        assert!(matches!(
            HostOverflowUid::read_at(&garbage),
            Err(SafetyNetUidError::OverflowUidUnreadable { .. })
        ));

        let missing = dir.path().join("does-not-exist");
        assert!(matches!(
            HostOverflowUid::read_at(&missing),
            Err(SafetyNetUidError::OverflowUidUnreadable { .. })
        ));
    }

    #[test]
    fn fs_overflowuid_is_never_the_one_read() {
        // A host may configure kernel.overflowuid and fs.overflowuid to different
        // values; reading the fs one would refuse the wrong uid and admit the
        // credential-collision value.
        let dir = tempfile::tempdir().expect("tempdir");
        let kernel = dir.path().join("kernel_overflowuid");
        let fs = dir.path().join("fs_overflowuid");
        std::fs::write(&kernel, "65534\n").expect("write");
        std::fs::write(&fs, "60000\n").expect("write");
        let host = HostOverflowUid::read_at(&kernel).expect("kernel value");
        assert_eq!(host.value(), 65534);
        assert!(validate_safety_net_uid(60000, host).is_ok());
        assert!(OVERFLOW_UID_SYSCTL_PATH.contains("/kernel/"));
    }

    #[test]
    fn an_empty_confined_set_is_refused() {
        assert_eq!(
            ConfinedUidSet::from_validated(Vec::new()),
            Err(SafetyNetUidError::EmptySet)
        );
    }

    #[test]
    fn the_confined_set_is_sorted_and_deduplicated() {
        let host = fixture_host();
        let set = ConfinedUidSet::from_validated(vec![
            validate_safety_net_uid(60124, host).expect("valid"),
            validate_safety_net_uid(60123, host).expect("valid"),
            validate_safety_net_uid(60124, host).expect("valid"),
        ])
        .expect("non-empty");
        assert_eq!(set.uids(), vec![60123, 60124]);
        assert_eq!(set.len(), 2);
        assert!(!set.is_empty());
    }

    /// The privacy proof D1c asks for. `ConfinedUidSet` and
    /// `ValidatedSafetyNetUid` both have exactly one private tuple field, and this
    /// module exports no constructor that takes a raw `u32`, so no module outside
    /// this one can build either from an unvalidated number. This test states the
    /// property and exercises the only admitted path; a future edit that added a
    /// `pub` field or a `pub fn new(u32)` would make the module's doc comment and
    /// this test both false, and the reviewer's checklist is the enforcement.
    /// Item 12: the overflow type has no production raw constructor.
    ///
    /// Structural, by reading this module's own source: the only `pub fn` that yields a
    /// `HostOverflowUid` outside a `#[cfg(test)]` block must be one of the two readers.
    /// A future edit adding a public raw constructor would have to change this
    /// assertion, which is the point.
    #[test]
    fn the_overflow_type_has_no_production_raw_constructor() {
        let source = include_str!("safety_net_uid.rs");
        let impl_start = source
            .find("impl HostOverflowUid {")
            .expect("the impl block is in this file");
        let impl_end = source[impl_start..]
            .find("\n}\n")
            .map(|o| impl_start + o)
            .expect("the impl block ends");
        let block = &source[impl_start..impl_end];
        // `from_value` is the only raw mint and it is test-gated.
        let from_value_at = block.find("fn from_value").expect("from_value exists");
        assert!(
            block[..from_value_at].contains("#[cfg(test)]"),
            "the raw constructor must be test-gated, so production cannot choose an \
             overflow value instead of reading the host's"
        );
        assert!(
            !block.contains("pub fn from_value"),
            "the raw constructor must not be public"
        );
        // And the two readers are present and public.
        assert!(block.contains("pub fn from_host"));
        assert!(block.contains("pub fn read_at"));
    }

    /// Grok B: the raw-uid construction proof for `ConfinedUidSet`.
    ///
    /// Structural for the same reason as above: the set's only constructor takes
    /// already-validated values, and no public entry accepts a raw `u32` or a raw
    /// collection. A caller elsewhere in the crate therefore cannot place an
    /// unattestable number into rule 1 even deliberately.
    #[test]
    fn the_confined_set_has_no_raw_uid_constructor() {
        // Scan the PRODUCTION half only: the test module below names these tokens in
        // its own assertions, and a scan that included itself would always fire.
        let whole = include_str!("safety_net_uid.rs");
        let source = &whole[..whole
            .find("#[cfg(test)]\nmod tests {")
            .expect("the test module marks the end of the production half")];
        let impl_start = source
            .find("impl ConfinedUidSet {")
            .expect("the impl block is in this file");
        let impl_end = source[impl_start..]
            .find("\n}\n")
            .map(|o| impl_start + o)
            .expect("the impl block ends");
        let block = &source[impl_start..impl_end];
        assert!(
            block.contains("pub fn from_validated"),
            "the validated constructor is the admitted path"
        );
        for forbidden in [
            "pub fn new(",
            "pub fn from_uids",
            "pub fn from_raw",
            "impl Default for ConfinedUidSet",
            "pub fn empty(",
        ] {
            assert!(
                !source.contains(forbidden),
                "no public raw or empty constructor may exist: found {forbidden}"
            );
        }
        // The field is private, so a struct literal is unavailable outside this module.
        assert!(
            source.contains("pub struct ConfinedUidSet(Vec<ValidatedSafetyNetUid>);"),
            "the single field stays private"
        );
        // And the element type's own field is private for the same reason.
        assert!(source.contains("pub struct ValidatedSafetyNetUid(u32);"));
    }

    #[test]
    fn safety_net_scope_is_closed_to_raw_uids() {
        let host = fixture_host();
        // The ONLY way to a set: validate, then collect.
        let validated = validate_safety_net_uid(60123, host).expect("valid");
        assert!(ConfinedUidSet::from_validated(vec![validated]).is_ok());
        // And every refused value stops at the validator, so it can never reach
        // a set at all.
        for refused in [0u32, FIXTURE_OVERFLOW_UID, INVALID_UID_SENTINEL] {
            let err = validate_safety_net_uid(refused, host)
                .expect_err("an unattestable uid never mints");
            assert!(!format!("{err}").is_empty());
        }
    }
}
