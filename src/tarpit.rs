//! Budget for deliberately-slow responses.
//!
//! Every trap that holds a request open — the credential tarpit (up to 240 s),
//! the recon ladder, and the streamed heapdump — consumes one of the service's
//! finite concurrent request slots for its whole duration. Cloud Run gives us
//! `containerConcurrency` 80 across `maxScale` 3, so 240 slots: not the
//! per-instance exclusivity a naive reading suggests, but still a hard ceiling.
//! Held long enough and in enough parallel, delaying responses would fill it
//! and the service would stop accepting new probes — the honeypot tarpitting
//! itself out of existence.
//!
//! So holding is a budgeted resource. A trap reserves a slot before it delays.
//! If the budget is exhausted it answers immediately instead: a fast response
//! is unremarkable to an attacker, whereas a request the platform kills at the
//! 300 s timeout returns a 504 that identifies the trap outright. Wasting
//! attacker time is the goal, but never at the cost of being unable to record
//! the next one.

use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub type Budget = Arc<Semaphore>;

pub fn new_budget(slots: usize) -> Budget {
    Arc::new(Semaphore::new(slots))
}

/// Reserve a slow-response slot without waiting.
///
/// `Some(permit)` means this request may hold; the slot is released when the
/// permit drops. `None` means the budget is spent and the caller must respond
/// immediately — and must log a delay of 0, because that is what happened.
pub fn try_reserve(budget: &Budget) -> Option<OwnedSemaphorePermit> {
    Arc::clone(budget).try_acquire_owned().ok()
}

/// The delay actually applied, given the desired delay and whether a slot was
/// reserved. Kept as its own function so the logged `response_delay_ms` can
/// never drift from the sleep that follows it — an inflated delay column would
/// silently overstate "attacker time wasted" on the dashboard.
pub fn effective_delay(desired: u64, permit: &Option<OwnedSemaphorePermit>) -> u64 {
    if permit.is_some() {
        desired
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_hands_out_exactly_its_slots() {
        let b = new_budget(2);
        let a = try_reserve(&b);
        let c = try_reserve(&b);
        assert!(a.is_some() && c.is_some());
        assert!(try_reserve(&b).is_none(), "third request must not hold");
        drop(a);
        assert!(try_reserve(&b).is_some(), "slot returns when the hold ends");
    }

    #[test]
    fn effective_delay_is_zero_without_a_slot() {
        let b = new_budget(1);
        let held = try_reserve(&b);
        assert_eq!(effective_delay(240, &held), 240);
        let denied = try_reserve(&b);
        assert!(denied.is_none());
        assert_eq!(
            effective_delay(240, &denied),
            0,
            "logged delay must match reality"
        );
    }

    #[test]
    fn zero_budget_disables_holding_entirely() {
        let b = new_budget(0);
        assert!(try_reserve(&b).is_none());
    }
}
