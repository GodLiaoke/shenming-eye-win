//! Request generations: forgetting/replacing a card cancels backoff and makes
//! every older completion and renewal timer incapable of changing GUI state.
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
#[derive(Clone, Debug, Default)]
pub(crate) struct Cancellation(Arc<(Mutex<bool>, Condvar)>);
impl Cancellation {
    pub(crate) fn cancel(&self) {
        let (lock, cv) = &*self.0;
        *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
        cv.notify_all();
    }
    pub(crate) fn is_cancelled(&self) -> bool {
        *self.0.0.lock().unwrap_or_else(|e| e.into_inner())
    }
    /// Returns false immediately when cancelled, including during a backoff.
    pub(crate) fn wait(&self, duration: Duration) -> bool {
        let (lock, cv) = &*self.0;
        let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        let (guard, _) = cv
            .wait_timeout_while(guard, duration, |cancelled| !*cancelled)
            .unwrap_or_else(|e| e.into_inner());
        !*guard
    }
}
#[derive(Clone, Debug)]
pub(crate) struct Ticket {
    pub(crate) generation: u64,
    pub(crate) cancel: Cancellation,
}
#[derive(Default)]
pub(crate) struct Requests {
    generation: u64,
    current: Option<Ticket>,
    busy: bool,
}
impl Requests {
    pub(crate) fn begin(&mut self) -> Ticket {
        self.invalidate();
        self.busy = true;
        let ticket = Ticket {
            generation: self.generation,
            cancel: Cancellation::default(),
        };
        self.current = Some(ticket.clone());
        ticket
    }
    pub(crate) fn invalidate(&mut self) {
        if let Some(ticket) = self.current.take() {
            ticket.cancel.cancel();
        }
        self.generation = self.generation.wrapping_add(1);
        self.busy = false;
    }
    pub(crate) fn accepts(&self, generation: u64) -> bool {
        self.current
            .as_ref()
            .is_some_and(|t| t.generation == generation && !t.cancel.is_cancelled())
    }
    pub(crate) fn finish(&mut self, generation: u64) -> bool {
        if !self.accepts(generation) {
            return false;
        }
        self.busy = false;
        true
    }
    pub(crate) fn busy(&self) -> bool {
        self.busy
    }
    pub(crate) fn ticket(&self) -> Option<Ticket> {
        self.current.clone()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn forget_rejects_inflight_success() {
        let mut r = Requests::default();
        let old = r.begin();
        r.invalidate();
        assert!(!r.finish(old.generation));
        assert!(old.cancel.is_cancelled());
    }
    #[test]
    fn new_card_rejects_old_failure() {
        let mut r = Requests::default();
        let old = r.begin();
        let new = r.begin();
        assert!(!r.finish(old.generation));
        assert!(r.busy());
        assert!(r.finish(new.generation));
        assert!(!r.busy());
    }
    #[test]
    fn old_renew_timer_cannot_restore_authorization() {
        let mut r = Requests::default();
        let old = r.begin();
        r.finish(old.generation);
        r.begin();
        assert!(!r.accepts(old.generation));
    }
    #[test]
    fn completion_keeps_live_timer_ticket() {
        let mut r = Requests::default();
        let t = r.begin();
        assert!(r.finish(t.generation));
        assert!(r.accepts(t.generation));
        assert!(r.ticket().is_some());
    }
    #[test]
    fn cancel_interrupts_backoff() {
        let c = Cancellation::default();
        let other = c.clone();
        let start = std::time::Instant::now();
        let worker = std::thread::spawn(move || other.wait(Duration::from_secs(30)));
        c.cancel();
        assert!(!worker.join().unwrap());
        assert!(start.elapsed() < Duration::from_secs(1));
    }
    #[test]
    fn wait_without_cancel_finishes() {
        assert!(Cancellation::default().wait(Duration::from_millis(1)));
    }
}
