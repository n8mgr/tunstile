use std::time::Duration;

use tunstile_protocol::{
    peer::{
        KEEPALIVE_TIMEOUT, REJECT_AFTER_TIME, REKEY_AFTER_TIME, REKEY_AFTER_TIME_RECEIVING,
        REKEY_ATTEMPT_TIME, REKEY_TIMEOUT, REKEY_TIMEOUT_JITTER_MAX,
    },
    time::Instant as Timestamp,
};

fn rekey_jitter() -> Duration {
    Duration::from_millis(rand::random_range(
        0..REKEY_TIMEOUT_JITTER_MAX.as_millis() as u64,
    ))
}

#[derive(Clone, Copy)]
pub(super) struct HandshakeTimers {
    first_sent: Timestamp,
    retry_at: Timestamp,
}

impl HandshakeTimers {
    pub(super) fn new(first_sent: Timestamp, now: Timestamp) -> Self {
        Self {
            first_sent,
            retry_at: now + REKEY_TIMEOUT + rekey_jitter(),
        }
    }

    pub(super) fn first_sent(&self) -> Timestamp {
        self.first_sent
    }

    pub(super) fn next_deadline(&self) -> Timestamp {
        self.retry_at
    }

    pub(super) fn due(&self, now: Timestamp) -> bool {
        now >= self.retry_at
    }

    pub(super) fn attempts_exhausted(&self, now: Timestamp) -> bool {
        now.duration_since(self.first_sent) >= REKEY_ATTEMPT_TIME
    }
}

#[derive(Default)]
pub(super) struct SessionDue {
    pub(super) keepalive: bool,
    pub(super) new_handshake: bool,
}

pub(super) struct SessionTimers {
    initiator: bool,
    established: Timestamp,
    last_send: Timestamp,
    keepalive_at: Option<Timestamp>,
    new_handshake_at: Option<Timestamp>,
}

impl SessionTimers {
    pub(super) fn new(initiator: bool, now: Timestamp) -> Self {
        Self {
            initiator,
            established: now,
            last_send: now,
            keepalive_at: None,
            new_handshake_at: None,
        }
    }

    pub(super) fn data_sent(&mut self, now: Timestamp) {
        self.last_send = now;
        self.keepalive_at = None;
        self.new_handshake_at
            .get_or_insert(now + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT + rekey_jitter());
    }

    pub(super) fn keepalive_sent(&mut self, now: Timestamp) {
        self.last_send = now;
        self.keepalive_at = None;
    }

    pub(super) fn packet_received(&mut self, now: Timestamp, carried_payload: bool) {
        self.new_handshake_at = None;
        if carried_payload {
            self.keepalive_at.get_or_insert(now + KEEPALIVE_TIMEOUT);
        }
    }

    pub(super) fn expired(&self, now: Timestamp) -> bool {
        now >= self.expires_at()
    }

    pub(super) fn rekey_after_send(&self, now: Timestamp) -> bool {
        self.initiator && now.duration_since(self.established) >= REKEY_AFTER_TIME
    }

    pub(super) fn rekey_after_receive(&self, now: Timestamp) -> bool {
        self.initiator && now.duration_since(self.established) >= REKEY_AFTER_TIME_RECEIVING
    }

    pub(super) fn next_deadline(&self, keepalive: Option<Duration>) -> Timestamp {
        [
            self.keepalive_at,
            self.new_handshake_at,
            self.persistent_keepalive_at(keepalive),
        ]
        .into_iter()
        .flatten()
        .fold(self.expires_at(), Timestamp::min)
    }

    pub(super) fn due(&mut self, now: Timestamp, keepalive: Option<Duration>) -> SessionDue {
        let mut due = SessionDue::default();
        if self.keepalive_at.is_some_and(|at| now >= at) {
            self.keepalive_at = None;
            due.keepalive = true;
        }
        if self
            .persistent_keepalive_at(keepalive)
            .is_some_and(|at| now >= at)
        {
            due.keepalive = true;
        }
        if self.new_handshake_at.is_some_and(|at| now >= at) {
            self.new_handshake_at = None;
            due.new_handshake = true;
        }
        due
    }

    fn expires_at(&self) -> Timestamp {
        self.established + REJECT_AFTER_TIME
    }

    fn persistent_keepalive_at(&self, interval: Option<Duration>) -> Option<Timestamp> {
        interval.map(|interval| self.last_send + interval)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timestamp(duration: Duration) -> Timestamp {
        Timestamp::from_millis(duration.as_millis() as u64)
    }

    #[test]
    fn rekey_jitter_stays_within_the_spec_bound() {
        for _ in 0..100 {
            assert!(rekey_jitter() < REKEY_TIMEOUT_JITTER_MAX);
        }
    }

    #[test]
    fn handshake_retries_after_rekey_timeout_and_gives_up_after_attempt_time() {
        let first_sent = Timestamp::from_millis(0);
        let handshake = HandshakeTimers::new(first_sent, first_sent);

        assert_eq!(handshake.first_sent(), first_sent);
        assert!(handshake.next_deadline() >= first_sent + REKEY_TIMEOUT);
        assert!(handshake.next_deadline() < first_sent + REKEY_TIMEOUT + REKEY_TIMEOUT_JITTER_MAX);
        assert!(!handshake.due(first_sent));
        assert!(handshake.due(handshake.next_deadline()));

        assert!(
            !handshake.attempts_exhausted(timestamp(REKEY_ATTEMPT_TIME - Duration::from_millis(1)))
        );
        assert!(handshake.attempts_exhausted(timestamp(REKEY_ATTEMPT_TIME)));
    }

    #[test]
    fn initiator_rekeys_on_receive_before_session_expiry() {
        let established = Timestamp::from_millis(0);
        let initiator = SessionTimers::new(true, established);
        let responder = SessionTimers::new(false, established);
        let just_before = REKEY_AFTER_TIME_RECEIVING - Duration::from_millis(1);

        assert!(!initiator.rekey_after_receive(timestamp(just_before)));
        assert!(initiator.rekey_after_receive(timestamp(REKEY_AFTER_TIME_RECEIVING)));
        assert!(!responder.rekey_after_receive(timestamp(REKEY_AFTER_TIME_RECEIVING)));
        assert_eq!(REKEY_AFTER_TIME_RECEIVING, Duration::from_secs(165));
    }

    #[test]
    fn initiator_rekeys_on_send_after_rekey_time() {
        let established = Timestamp::from_millis(0);
        let initiator = SessionTimers::new(true, established);
        let responder = SessionTimers::new(false, established);
        let just_before = REKEY_AFTER_TIME - Duration::from_millis(1);

        assert!(!initiator.rekey_after_send(timestamp(just_before)));
        assert!(initiator.rekey_after_send(timestamp(REKEY_AFTER_TIME)));
        assert!(!responder.rekey_after_send(timestamp(REKEY_AFTER_TIME)));
    }

    #[test]
    fn an_idle_session_only_wakes_to_expire() {
        let established = Timestamp::from_millis(0);
        let session = SessionTimers::new(true, established);

        assert_eq!(session.next_deadline(None), timestamp(REJECT_AFTER_TIME));
        assert!(!session.expired(timestamp(REJECT_AFTER_TIME - Duration::from_millis(1))));
        assert!(session.expired(timestamp(REJECT_AFTER_TIME)));
    }

    #[test]
    fn persistent_keepalive_sets_the_deadline_from_the_last_send() {
        let established = Timestamp::from_millis(0);
        let interval = Duration::from_secs(25);
        let mut session = SessionTimers::new(true, established);

        assert_eq!(session.next_deadline(Some(interval)), timestamp(interval));

        let sent_at = timestamp(Duration::from_secs(10));
        session.keepalive_sent(sent_at);
        assert_eq!(session.next_deadline(Some(interval)), sent_at + interval);

        assert!(
            !session
                .due(
                    sent_at + (interval - Duration::from_millis(1)),
                    Some(interval)
                )
                .keepalive
        );
        assert!(session.due(sent_at + interval, Some(interval)).keepalive);
    }

    #[test]
    fn received_payload_owes_a_passive_keepalive() {
        let now = Timestamp::from_millis(0);
        let mut session = SessionTimers::new(false, now);

        session.packet_received(now, false);
        assert_eq!(session.next_deadline(None), timestamp(REJECT_AFTER_TIME));

        session.packet_received(now, true);
        assert_eq!(session.next_deadline(None), now + KEEPALIVE_TIMEOUT);

        let due = session.due(now + KEEPALIVE_TIMEOUT, None);
        assert!(due.keepalive);
        assert!(!due.new_handshake);
        assert_eq!(session.next_deadline(None), timestamp(REJECT_AFTER_TIME));
    }

    #[test]
    fn unanswered_data_arms_a_new_handshake() {
        let now = Timestamp::from_millis(0);
        let mut session = SessionTimers::new(true, now);
        let earliest = now + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT;

        session.data_sent(now);
        let deadline = session.next_deadline(None);
        assert!(deadline >= earliest && deadline < earliest + REKEY_TIMEOUT_JITTER_MAX);

        session.data_sent(now + Duration::from_secs(1));
        assert_eq!(session.next_deadline(None), deadline);

        assert!(session.due(deadline, None).new_handshake);
        assert_eq!(session.next_deadline(None), timestamp(REJECT_AFTER_TIME));

        session.data_sent(now);
        session.packet_received(now, false);
        assert_eq!(session.next_deadline(None), timestamp(REJECT_AFTER_TIME));
    }

    #[test]
    fn firing_a_deadline_always_advances_the_next_one() {
        let interval = Duration::from_secs(25);
        let start = Timestamp::from_millis(0);

        let mut session = SessionTimers::new(true, start);
        session.packet_received(start, true);
        let at = session.next_deadline(None);
        assert!(session.due(at, None).keepalive);
        session.keepalive_sent(at);
        assert!(session.next_deadline(None) > at);

        let mut session = SessionTimers::new(true, start);
        let at = session.next_deadline(Some(interval));
        assert!(session.due(at, Some(interval)).keepalive);
        session.keepalive_sent(at);
        assert_eq!(session.next_deadline(Some(interval)), at + interval);

        let mut session = SessionTimers::new(true, start);
        session.data_sent(start);
        let at = session.next_deadline(None);
        assert!(session.due(at, None).new_handshake);
        assert!(session.next_deadline(None) > at);
    }

    #[test]
    fn keepalive_and_new_handshake_deadlines_are_exclusive() {
        let now = Timestamp::from_millis(0);
        let mut session = SessionTimers::new(true, now);

        session.packet_received(now, true);
        assert_eq!(session.keepalive_at, Some(now + KEEPALIVE_TIMEOUT));
        session.data_sent(now);
        assert_eq!(session.keepalive_at, None);
        assert!(session.new_handshake_at.is_some());

        session.packet_received(now, true);
        assert_eq!(session.new_handshake_at, None);
        assert_eq!(session.keepalive_at, Some(now + KEEPALIVE_TIMEOUT));
    }
}
