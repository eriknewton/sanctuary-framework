//! Pure admission ceilings. Admission never constructs an effect permit or freezes a body.
use super::{drain_protocol::D_REQUEST_DEADLINE_MS, signer_contract::*};
pub const FINISH_SECONDS: u64 = 2 * 3 * 4 + 30 + 60;
pub const FINISH_MS: u64 = FINISH_SECONDS * 1000;
pub const GRANT_FLOW_CAP: u64 = ((UNLOCK_TTL_MAX_SECONDS as u64 - H_LEASE_REQUEST_SECONDS as u64)
    * 1000
    / (SIGNER_REQUEST_DEADLINE_MS + LINUX_RECORD_DURABILITY_DEADLINE_MS) as u64
    - FINAL_CONTROL_RECORDS as u64)
    / 2;
pub const APPEND_BUDGET_MS: u64 = 3 * D_REQUEST_DEADLINE_MS as u64
    + SIGNER_REQUEST_DEADLINE_MS as u64
    + LINUX_RECORD_DURABILITY_DEADLINE_MS as u64;
const _: () = assert!(GRANT_FLOW_CAP == 13 && FINISH_SECONDS == 114 && APPEND_BUDGET_MS == 5000);
pub fn seal_ms(flows: u64) -> Option<u64> {
    flows
        .checked_mul(2)?
        .checked_add(FINAL_CONTROL_RECORDS as u64)?
        .checked_mul((SIGNER_REQUEST_DEADLINE_MS + LINUX_RECORD_DURABILITY_DEADLINE_MS) as u64)
}
/// Extracted because the residency inequality dominates this strict predicate.
pub fn finish_admitted(remaining_ms: u64, seal: u64) -> bool {
    FINISH_MS
        .checked_add(seal)
        .map(|minimum| remaining_ms > minimum)
        .unwrap_or(false)
}
/// Producer expiry comes from the independently authenticated S grant.
// ProducerExpiry requires a concrete grant; this type must stay paired with the absent-grant status check in append_actor.rs::independent.
#[derive(Clone, Copy, Debug)]
pub struct ProducerExpiry {
    grant: [u8; 16],
    at_ms: u64,
}
/// H expiry comes from the independent H lease observation, never a candidate body.
#[derive(Clone, Copy, Debug)]
pub struct HExpiry {
    at_ms: u64,
}
#[derive(Clone, Copy, Debug)]
pub struct RecheckInputs {
    observed_ms: u64,
    producer: ProducerExpiry,
    h: HExpiry,
}
/// An admission snapshot can be consumed by only one append window.
/// ```compile_fail,E0382
/// use castle_wall_daemon::business_profile::append_budget::BudgetSnapshot;
/// fn retry(snapshot: BudgetSnapshot) {
///     let _first = snapshot.begin_append(0, 10000);
///     let _second = snapshot.begin_append(4000, 10000);
/// }
/// ```
/// A snapshot cannot be cloned to open another window.
/// ```compile_fail,E0599
/// use castle_wall_daemon::business_profile::append_budget::BudgetSnapshot;
/// fn duplicate(snapshot: BudgetSnapshot) {
///     let _copy = snapshot.clone();
/// }
/// ```
#[derive(Debug)]
pub struct BudgetSnapshot {
    grant: [u8; 16],
    producer_expiry: u64,
    h_expiry: u64,
    seal: u64,
    observed_ms: u64,
}
// Ambiguous trait selection is a compile-time assertion, including on Rust 1.75.
// Each bound must remain absent from the owned admission snapshot.
const _: fn() = || {
    trait AmbiguousIfClone<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    struct Cloned;
    impl<T: Clone> AmbiguousIfClone<Cloned> for T {}
    let _ = <BudgetSnapshot as AmbiguousIfClone<_>>::check;

    trait AmbiguousIfCopy<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfCopy<()> for T {}
    struct Copied;
    impl<T: Copy> AmbiguousIfCopy<Copied> for T {}
    let _ = <BudgetSnapshot as AmbiguousIfCopy<_>>::check;
};
impl ProducerExpiry {
    /// Isolated fixture access to the same expiry checks used by composition.
    #[cfg(any(test, feature = "test-isolation"))]
    pub fn checked_for_test(grant: [u8; 16], at_ms: u64, observed_ms: u64) -> Option<Self> {
        Self::checked(grant, at_ms, observed_ms)
    }
    /// Composition supplies the authenticated producer grant and its absolute expiry.
    #[cfg_attr(not(any(test, feature = "test-isolation")), allow(dead_code))]
    pub(crate) fn checked(grant: [u8; 16], at_ms: u64, observed_ms: u64) -> Option<Self> {
        // Freshness is dominated by BudgetSnapshot::append_deadline's original-window clamp; changing that bound reopens this predicate's evidence obligation.
        (at_ms > observed_ms).then_some(Self { grant, at_ms })
    }
}
impl HExpiry {
    /// Isolated fixture access to the same expiry checks used by composition.
    #[cfg(any(test, feature = "test-isolation"))]
    pub fn checked_for_test(at_ms: u64, observed_ms: u64) -> Option<Self> {
        Self::checked(at_ms, observed_ms)
    }
    /// Composition supplies the independently observed H lease's absolute expiry.
    #[cfg_attr(not(any(test, feature = "test-isolation")), allow(dead_code))]
    pub(crate) fn checked(at_ms: u64, observed_ms: u64) -> Option<Self> {
        // Freshness is dominated by BudgetSnapshot::append_deadline's original-window clamp; changing that bound reopens this predicate's evidence obligation.
        (at_ms > observed_ms).then_some(Self { at_ms })
    }
}
impl RecheckInputs {
    /// Isolated fixture access to the same expiry checks used by composition.
    #[cfg(any(test, feature = "test-isolation"))]
    pub fn checked_for_test(
        observed_ms: u64,
        producer: ProducerExpiry,
        h: HExpiry,
    ) -> Option<Self> {
        Self::checked(observed_ms, producer, h)
    }
    /// Refuse expired observations before they can enter admission or completion.
    #[cfg_attr(not(any(test, feature = "test-isolation")), allow(dead_code))]
    pub(crate) fn checked(observed_ms: u64, producer: ProducerExpiry, h: HExpiry) -> Option<Self> {
        // Freshness is dominated by BudgetSnapshot::append_deadline's original-window clamp; changing that bound reopens this predicate's evidence obligation.
        (observed_ms < producer.at_ms && observed_ms < h.at_ms).then_some(Self {
            observed_ms,
            producer,
            h,
        })
    }
}
pub fn admit(input: RecheckInputs, flows: u64) -> Option<BudgetSnapshot> {
    if flows > GRANT_FLOW_CAP {
        return None;
    }
    let seal = seal_ms(flows)?;
    let producer = input.producer.at_ms.checked_sub(input.observed_ms)?;
    let h = input.h.at_ms.checked_sub(input.observed_ms)?;
    // Each independent clock obligation must fit; equality is closed for finish.
    if !finish_admitted(producer, seal)
        || !finish_admitted(h, seal)
        || producer < (H_LEASE_REQUEST_SECONDS as u64 * 1000).checked_add(seal)?
    {
        return None;
    }
    Some(BudgetSnapshot {
        grant: input.producer.grant,
        producer_expiry: input.producer.at_ms,
        h_expiry: input.h.at_ms,
        seal,
        observed_ms: input.observed_ms,
    })
}
impl BudgetSnapshot {
    fn append_deadline(&self, now_ms: u64, caller_deadline: u64) -> Option<u64> {
        if now_ms < self.observed_ms {
            return None;
        }
        let deadline = now_ms
            .checked_add(APPEND_BUDGET_MS)?
            .min(caller_deadline)
            // This producer clamp must stay paired with ProducerExpiry/RecheckInputs freshness and BudgetSnapshot::recheck's producer end comparison.
            .min(self.producer_expiry.checked_sub(self.seal)?)
            // This H clamp must stay paired with HExpiry/RecheckInputs freshness and BudgetSnapshot::recheck's H end comparison.
            .min(self.h_expiry.checked_sub(self.seal)?);
        (now_ms < deadline).then_some(deadline)
    }
    /// One snapshot opens at most one window. Preventing re-admission after a
    /// deadline is the K1c-2e2 caller's obligation.
    pub fn begin_append(self, now_ms: u64, caller_deadline: u64) -> Option<AppendWindow> {
        let deadline_ms = self.append_deadline(now_ms, caller_deadline)?;
        Some(AppendWindow {
            snapshot: self,
            started_ms: now_ms,
            deadline_ms,
        })
    }
    fn recheck(&self, input: RecheckInputs, remaining_cost: u64, append_deadline: u64) -> bool {
        // Completion consumes the original absolute snapshot, never a fresh lease.
        // With a shared origin this lower bound is dominated by AppendWindow::recheck's start bound; each must stay paired and changing either reopens the other's evidence obligation.
        input.observed_ms >= self.observed_ms
            // The consumed producer identity must stay paired with complete-status lease-id equality in append_actor.rs::independent.
            && input.producer.grant == self.grant
            && input.producer.at_ms == self.producer_expiry
            && input.h.at_ms == self.h_expiry
            // This original-window bound must stay paired with ProducerExpiry, HExpiry and RecheckInputs freshness before completion.
            && input.observed_ms < append_deadline
            && input
                .observed_ms
                // Overflow is unreachable for append_actor.rs::independent's u64 nanoseconds divided by NS_PER_MS plus its bounded protocol cost; changing that range reopens this obligation.
                .checked_add(remaining_cost)
                .map(|end| {
                    // Both strict expiry checks are dominated by append_deadline's respective seal-reserve clamps; changing either clamp reopens its paired predicate's evidence obligation.
                    end <= append_deadline && end < self.producer_expiry && end < self.h_expiry
                })
                .unwrap_or(false)
    }
}
/// One owned append's absolute budget, created only by initial clamping.
#[derive(Debug)]
pub struct AppendWindow {
    snapshot: BudgetSnapshot,
    started_ms: u64,
    deadline_ms: u64,
}
impl AppendWindow {
    pub fn deadline_ms(&self) -> u64 {
        self.deadline_ms
    }
    pub fn recheck(&self, input: RecheckInputs, remaining_cost: u64) -> bool {
        // With a shared origin this start bound is dominated by BudgetSnapshot::recheck's observation bound; each must stay paired and changing either reopens the other's evidence obligation.
        input.observed_ms >= self.started_ms
            && self
                .snapshot
                .recheck(input, remaining_cost, self.deadline_ms)
    }
}
#[derive(Default, Debug)]
pub struct CutObligation {
    owned: Option<([u8; 16], u64)>,
}
impl CutObligation {
    pub fn retain(&mut self, grant: [u8; 16], unresolved: u64) -> bool {
        if unresolved == 0 {
            return false;
        }
        match self.owned {
            None => {
                self.owned = Some((grant, unresolved));
                true
            }
            Some((owner, count)) if owner == grant => match count.checked_add(unresolved) {
                Some(next) => {
                    self.owned = Some((owner, next));
                    true
                }
                None => false,
            },
            _ => false,
        }
    }
    /// Discharge only the exact count bound to a durably committed control for the owning grant.
    pub fn discharge(&mut self, grant: [u8; 16], count: u64) -> bool {
        if self.owned != Some((grant, count)) {
            return false;
        }
        self.owned = None;
        true
    }
    pub fn pending(&self) -> Option<([u8; 16], u64)> {
        self.owned
    }
}
