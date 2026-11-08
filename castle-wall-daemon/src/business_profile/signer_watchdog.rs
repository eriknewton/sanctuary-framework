//! Native, suspend-inclusive lease authority; the worker never owns this clock.
use super::signer_contract::{UNLOCKING_DEADLINE_SECONDS, UNLOCK_TTL_MAX_SECONDS};
use std::io;
use std::process::Child;

pub const NS_PER_SECOND: u64 = 1_000_000_000;
pub const WATCHDOG_TICK_MS: i32 = 10;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Locked,
    Unlocking,
    Unlocked,
    Locking,
    Wiped,
    WipeUnconfirmed,
    RecoveryRequired,
}
#[derive(Debug)]
pub struct Lease {
    pub state: State,
    started: u64,
    expires: u64,
    unlocking_end: u64,
}
impl Default for Lease {
    fn default() -> Self {
        Self {
            state: State::Locked,
            started: 0,
            expires: 0,
            unlocking_end: 0,
        }
    }
}
impl Lease {
    pub fn begin(&mut self, now: u64, ttl: u64) -> bool {
        // Attendance starts both deadlines so neither KDF nor READY can renew residency.
        if self.state != State::Locked || ttl == 0 || ttl > UNLOCK_TTL_MAX_SECONDS as u64 {
            return false;
        }
        let expires = match now.checked_add(ttl * NS_PER_SECOND) {
            Some(v) => v,
            None => return false,
        };
        let unlocking_end = match now.checked_add(UNLOCKING_DEADLINE_SECONDS as u64 * NS_PER_SECOND)
        {
            Some(v) => v,
            None => return false,
        };
        self.started = now;
        self.expires = expires;
        self.unlocking_end = unlocking_end;
        self.state = State::Unlocking;
        true
    }
    pub fn ready(&mut self, now: u64) -> bool {
        if self.state != State::Unlocking || !self.live(now) {
            return false;
        }
        self.state = State::Unlocked;
        true
    }
    pub fn live(&self, now: u64) -> bool {
        // A clock fault or suspend-inclusive expiry removes authority before any response is forwarded.
        now >= self.started
            && now < self.expires
            && match self.state {
                State::Unlocking => now < self.unlocking_end,
                State::Unlocked => true,
                _ => false,
            }
    }
    pub fn can_sign(&self, now: u64) -> bool {
        self.state == State::Unlocked && self.live(now)
    }
    pub fn expires(&self) -> u64 {
        self.expires
    }
    pub fn started(&self) -> u64 {
        self.started
    }
    pub fn revoke(&mut self) {
        self.state = State::Locking;
    }
    pub fn reaped(&mut self, cooperative: bool) {
        // Cleanup acknowledgement alone is insufficient because immutable library copies die only with the process.
        self.state = if cooperative {
            State::Wiped
        } else {
            State::WipeUnconfirmed
        };
    }
}
pub fn boottime_ns() -> io::Result<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) } != 0 {
        return Err(io::Error::last_os_error());
    }
    (ts.tv_sec as u64)
        .checked_mul(NS_PER_SECOND)
        .and_then(|v| v.checked_add(ts.tv_nsec as u64))
        .ok_or_else(|| io::Error::other("K1_REFUSED"))
}
pub fn kill_and_reap(child: &mut Child, lease: &mut Lease) -> io::Result<()> {
    lease.revoke();
    if child.try_wait()?.is_none() {
        child.kill()?;
    }
    child.wait()?;
    lease.reaped(false);
    Ok(())
}
