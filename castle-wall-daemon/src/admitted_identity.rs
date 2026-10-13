use crate::manifest::ManifestStoreError;
use crate::policy::PolicySnapshot;

/// The identity this process is armed with after boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdmittedIdentity {
    /// The fortress the boot snapshot was admitted under. Must match
    /// `PolicySnapshot::fortress_id` in `src/policy.rs` and
    /// `AgentRulesetId::fortress_id` in `src/nftables.rs`, which reads it from here.
    fortress_id: String,
    /// Who the manifest confines, if anyone.
    subject: AdmittedSubject,
}

/// Who a manifest confines. The two variants are not interchangeable: a kernel
/// binding is legitimate under exactly one of them, so collapsing them into an
/// `Option<u32>` would lose the difference between "this manifest confines
/// nobody" and "this manifest's confinement is unknown".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmittedSubject {
    /// The manifest admits no agent uid. No per-agent binding may be live.
    Unconfined,
    /// The manifest admits `agent_uid` under `ceiling`, optionally beside a
    /// distinct `gate_uid`. All three move together (see `PolicySnapshot`).
    Confined {
        agent_uid: u32,
        ceiling: u32,
        gate_uid: Option<u32>,
    },
}

impl AdmittedIdentity {
    /// Derive the armed identity from a COMMITTED policy snapshot.
    ///
    /// INVARIANT this enforces at the point of derivation, and it is SYMMETRIC:
    /// `confined_agent_uid` and `confined_agent_uid_ceiling` are `Some` together
    /// or not at all (`PolicySnapshot` states it;
    /// `snapshot_threads_the_whole_admitted_set` asserts it). A uid with no
    /// ceiling would mean sealing a uid into a kernel rule without the floor
    /// admission accepted it under. A ceiling with NO uid is the same invalid
    /// state seen from the other side: the snapshot carries an admission bound
    /// that no subject was derived from, so reading it as `Unconfined` would
    /// silently discard half of an inconsistent pair and arm a wall that confines
    /// nobody under a manifest that meant to confine someone. Both are refused
    /// here rather than defaulted.
    pub(crate) fn from_snapshot(snapshot: &PolicySnapshot) -> Result<Self, String> {
        let subject = match (
            snapshot.confined_agent_uid,
            snapshot.confined_agent_uid_ceiling,
        ) {
            (None, None) => AdmittedSubject::Unconfined,
            (Some(agent_uid), Some(ceiling)) => AdmittedSubject::Confined {
                agent_uid,
                ceiling,
                gate_uid: snapshot.confined_gate_uid,
            },
            (Some(agent_uid), None) => {
                return Err(format!(
                    "the policy snapshot confines uid {agent_uid} with no admission ceiling; \
                     the two are set together or not at all"
                ))
            }
            (None, Some(ceiling)) => {
                return Err(format!(
                    "the policy snapshot carries an admission ceiling {ceiling} with no confined \
                     uid; the two are set together or not at all"
                ))
            }
        };
        Ok(Self {
            fortress_id: snapshot.fortress_id.clone(),
            subject,
        })
    }

    pub(crate) fn from_boot(source: BootAdmittedIdentity) -> Self {
        Self {
            fortress_id: source.fortress_id,
            subject: source.subject,
        }
    }

    pub(crate) fn fortress_id(&self) -> &str {
        &self.fortress_id
    }

    pub(crate) fn subject(&self) -> AdmittedSubject {
        self.subject
    }
}

/// Boot-only identity source. Confined fields enter here from the boot-time
/// scoped-rule refusal; structural tests pin the decision path's snapshot arm
/// to `from_snapshot`, its refused-identity arm to Unattributed, and subject
/// resolution to the next statement.
pub(crate) struct BootAdmittedIdentity {
    fortress_id: String,
    subject: AdmittedSubject,
}

impl BootAdmittedIdentity {
    pub(crate) fn confined_scope_refusal(
        fortress_id: &str,
        error: &ManifestStoreError,
    ) -> Option<Self> {
        let (agent_uid, ceiling, gate_uid) = error.boot_confined_subject()?;
        Some(Self {
            fortress_id: fortress_id.to_string(),
            subject: AdmittedSubject::Confined {
                agent_uid,
                ceiling,
                gate_uid,
            },
        })
    }

    pub(crate) fn unconfined(fortress_id: &str) -> Self {
        Self {
            fortress_id: fortress_id.to_string(),
            subject: AdmittedSubject::Unconfined,
        }
    }
}
