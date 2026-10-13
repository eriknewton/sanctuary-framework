/// Confined Linux subject named in egress audit evidence.
///
/// A bare agent name has no constructor; every identity_id the daemon signs
/// names a confined uid under a fortress. Must match `protectionSubjectForUid`
/// and `fortressIdFromProtectionSubject` in
/// `server/src/castle-wall/subject-binding.ts`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionSubject {
    fortress_id: String,
    uid: u32,
    rendered: String,
}

impl ProtectionSubject {
    pub fn new(fortress_id: &str, uid: u32) -> Option<Self> {
        if fortress_id.is_empty() || uid == 0 {
            return None;
        }
        Some(Self {
            fortress_id: fortress_id.to_string(),
            uid,
            rendered: format!("{fortress_id}/uid-{uid}"),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.rendered
    }

    pub fn fortress_id(&self) -> &str {
        &self.fortress_id
    }

    pub fn uid(&self) -> u32 {
        self.uid
    }
}
