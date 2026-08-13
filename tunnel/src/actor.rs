//! The per-peer driver: owns the sans-IO state machine, its liveness
//! schedule, and the staged-send queue.

use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime},
};

use log::debug;
use quinn_udp::BATCH_SIZE;
use tokio::{
    select,
    sync::{
        mpsc::{self, Receiver, Sender},
        watch,
    },
    time::{Instant, Sleep, sleep_until},
};
use tunstile_protocol::{
    PrivateKey, PublicKey, ReusableSecret, Tai64N,
    handshake::{Handshake, INIT_MSG_LENGTH, InitReceived, RESP_MSG_LENGTH},
    peer::{
        HandshakeValues, KEEPALIVE_TIMEOUT, Peer as PeerState, REJECT_AFTER_TIME, REKEY_AFTER_TIME,
        REKEY_AFTER_TIME_RECEIVING, REKEY_ATTEMPT_TIME, REKEY_TIMEOUT, REKEY_TIMEOUT_JITTER_MAX,
    },
    time::Instant as Timestamp,
    transport::Transport,
};

use crate::{
    Packet, PeerConfig, PeerStatus, PeerUpdate, Update, router::Control, socket::UdpSocket,
};

const MAX_STAGED_PACKETS: usize = 128;

#[derive(Clone, Copy)]
pub(crate) struct Clock {
    epoch: Instant,
}

impl Clock {
    pub(crate) fn new() -> Self {
        Self {
            epoch: Instant::now(),
        }
    }

    pub(crate) fn now(&self) -> Timestamp {
        self.epoch.elapsed().into()
    }

    /// `None` yields a sleep the gated select arm never polls; the arm's
    /// expression is still evaluated when its guard is false.
    fn sleep_until(&self, at: Option<Timestamp>) -> Sleep {
        sleep_until(self.epoch + Duration::from(at.unwrap_or_default()))
    }
}

fn rekey_jitter() -> Duration {
    Duration::from_millis(rand::random_range(
        0..REKEY_TIMEOUT_JITTER_MAX.as_millis() as u64,
    ))
}

#[derive(Clone, Copy)]
struct HandshakeAttempt {
    first_sent: Timestamp,
    retry_at: Timestamp,
}

impl HandshakeAttempt {
    fn new(first_sent: Timestamp, now: Timestamp) -> Self {
        Self {
            first_sent,
            retry_at: now + REKEY_TIMEOUT + rekey_jitter(),
        }
    }
}

struct Session {
    initiator: bool,
    established: Timestamp,
    expires_at: Timestamp,
    // a received payload awaits acknowledgement (passive keepalive)
    keepalive_at: Option<Timestamp>,
    // sent data went unanswered; assume the session died
    new_handshake_at: Option<Timestamp>,
}

impl Session {
    fn new(initiator: bool, now: Timestamp) -> Self {
        Self {
            initiator,
            established: now,
            expires_at: now + REJECT_AFTER_TIME,
            keepalive_at: None,
            new_handshake_at: None,
        }
    }

    fn data_sent(&mut self, now: Timestamp) {
        self.keepalive_at = None;
        self.new_handshake_at
            .get_or_insert(now + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT + rekey_jitter());
    }

    fn keepalive_sent(&mut self) {
        self.keepalive_at = None;
    }

    fn packet_received(&mut self, now: Timestamp, carried_payload: bool) {
        self.new_handshake_at = None;
        if carried_payload {
            self.keepalive_at.get_or_insert(now + KEEPALIVE_TIMEOUT);
        }
    }

    fn usable(&self, now: Timestamp) -> bool {
        now < self.expires_at
    }

    fn rekey_after_send(&self, now: Timestamp) -> bool {
        self.initiator && now.duration_since(self.established) >= REKEY_AFTER_TIME
    }

    fn rekey_after_receive(&self, now: Timestamp) -> bool {
        self.initiator && now.duration_since(self.established) >= REKEY_AFTER_TIME_RECEIVING
    }
}

pub(crate) enum PeerAction {
    Connect(SocketAddr),
    Update(PeerUpdate),
    SendData(Vec<u8>),
    RecvData(Vec<u8>, u32, SocketAddr),
    RecvHandshakeInit(Handshake<InitReceived>, SocketAddr),
    RecvHandshakeResp(Vec<u8>, SocketAddr),
    RecvCookieReply(Vec<u8>),
}

struct PeerActor {
    label: String,
    our_key: Arc<PrivateKey>,
    machine: PeerState,
    clock: Clock,

    control: mpsc::UnboundedSender<Control>,

    persistent_keepalive: Option<Duration>,
    // also advanced on failed keepalive attempts so the timer never spins
    last_send: Timestamp,
    handshake: Option<HandshakeAttempt>,
    session: Option<Session>,

    session_tx: watch::Sender<bool>,
    staged: VecDeque<Vec<u8>>,

    socket: Arc<UdpSocket>,

    status: Arc<RwLock<PeerStatus>>,

    inbound_tx: Sender<Packet>,
}

impl PeerActor {
    fn update_status<F>(&self, func: F)
    where
        F: FnOnce(&mut PeerStatus),
    {
        let mut status = self.status.write().unwrap();
        func(&mut status)
    }

    fn retire_index(&self, index: Option<u32>) {
        if let Some(index) = index {
            let _ = self.control.send(Control::Retire(index));
        }
    }

    fn bind_index(&self, index: u32) {
        let _ = self
            .control
            .send(Control::Bind(self.machine.peer_key().clone(), index));
    }

    /// Sends a fresh handshake initiation. Retransmits pass the original
    /// `first_sent` so the abandonment window stays anchored.
    async fn send_handshake(&mut self, first_sent: Timestamp) {
        let Some(endpoint) = self.machine.endpoint() else {
            return;
        };
        let now = self.clock.now();
        self.handshake = Some(HandshakeAttempt::new(first_sent, now));
        let index = rand::random();
        let mut msg = [0u8; INIT_MSG_LENGTH];
        let values = HandshakeValues {
            index,
            ephemeral_secret: ReusableSecret::random(),
            timestamp: Tai64N::now(),
        };
        let replaced = match self.machine.initiate(&self.our_key, values, &mut msg) {
            Ok(replaced) => replaced,
            Err(e) => {
                debug!("[{}] failed to create handshake: {:?}", self.label, e);
                return;
            }
        };
        self.retire_index(replaced);
        self.bind_index(index);
        if let Err(e) = self.socket.send(endpoint, &msg).await {
            debug!(
                "[{}] failed to send handshake initiation: {:?}",
                self.label, e
            );
            return;
        }
        debug!("[{}] sent handshake initiation to {}", self.label, endpoint);
        self.last_send = now;
        self.update_status(|status| {
            status.tx_bytes += msg.len() as u64;
            status.last_send = Some(SystemTime::now());
        });
    }

    async fn ensure_handshake(&mut self) {
        if self.handshake.is_none() {
            let now = self.clock.now();
            self.send_handshake(now).await;
        }
    }

    async fn apply_update(&mut self, update: PeerUpdate) {
        match update.preshared_key {
            Update::Keep => {}
            Update::Clear => self.machine.set_preshared_key(None),
            Update::Set(preshared_key) => self.machine.set_preshared_key(Some(preshared_key)),
        }
        match update.persistent_keepalive {
            Update::Keep => {}
            Update::Clear => self.persistent_keepalive = None,
            Update::Set(interval) => self.persistent_keepalive = Some(interval),
        }
        if let Some(endpoint) = update.endpoint {
            self.machine.set_endpoint(endpoint);
            self.update_status(|status| status.endpoint = Some(endpoint));
            self.ensure_handshake().await;
        }
    }

    /// The session became usable: flush staged sends, and as the initiator
    /// with nothing staged, confirm the session to the responder.
    async fn session_established(&mut self, initiator: bool) {
        let had_staged = !self.staged.is_empty();
        self.flush_staged().await;
        if initiator && !had_staged {
            self.send_keepalive().await;
        }
        self.session_tx.send_replace(true);
    }

    async fn handle_message(&mut self, action: PeerAction) {
        let now = self.clock.now();
        match action {
            PeerAction::Connect(endpoint) => {
                self.machine.set_endpoint(endpoint);
                self.update_status(|status| status.endpoint = Some(endpoint));
                self.ensure_handshake().await;
            }
            PeerAction::Update(update) => self.apply_update(update).await,
            PeerAction::SendData(payload) => {
                let mut payloads = vec![payload];
                self.flush_sends(&mut payloads).await;
            }
            PeerAction::RecvData(mut data, receiver, endpoint) => {
                let rx_bytes = data.len() as u64;
                match self.machine.decrypt(now, receiver, &mut data, endpoint) {
                    Ok(recv) => {
                        let confirmed = recv.confirmed;
                        let payload = (recv.payload_len > 0).then(|| {
                            data.truncate(recv.payload_len);
                            data
                        });
                        self.retire_index(recv.unmapped);
                        self.update_status(|status| {
                            status.endpoint = Some(endpoint);
                            status.rx_bytes += rx_bytes;
                            status.last_recv = Some(SystemTime::now());
                        });
                        if confirmed {
                            debug!("[{}] session confirmed", self.label);
                            self.session = Some(Session::new(false, now));
                        }
                        if let Some(session) = self.session.as_mut() {
                            session.packet_received(now, payload.is_some());
                        }
                        let rekey = self
                            .session
                            .as_ref()
                            .is_some_and(|session| session.rekey_after_receive(now));
                        if let Some(payload) = payload {
                            // drop on a full queue rather than await: a slow or absent
                            // reader must not stall the actor's timers and handshakes
                            let packet = Packet {
                                public_key: self.machine.peer_key().clone(),
                                payload,
                            };
                            if let Err(mpsc::error::TrySendError::Full(_)) =
                                self.inbound_tx.try_send(packet)
                            {
                                debug!(
                                    "[{}] dropping inbound packet: receive queue full",
                                    self.label
                                );
                            }
                        }
                        if confirmed {
                            self.session_established(false).await;
                        }
                        if rekey {
                            self.ensure_handshake().await;
                        }
                    }
                    Err(e) => debug!("[{}] dropping inbound packet: {:?}", self.label, e),
                }
            }
            PeerAction::RecvHandshakeInit(handshake, endpoint) => {
                let index = rand::random();
                let mut msg = [0u8; RESP_MSG_LENGTH];
                let values = HandshakeValues {
                    index,
                    ephemeral_secret: ReusableSecret::random(),
                    timestamp: Tai64N::now(),
                };
                let displaced = match self
                    .machine
                    .respond(now, handshake, values, endpoint, &mut msg)
                {
                    Ok(displaced) => displaced,
                    Err(e) => {
                        debug!("[{}] dropping handshake initiation: {:?}", self.label, e);
                        return;
                    }
                };
                self.retire_index(displaced);
                self.bind_index(index);
                if let Err(e) = self.socket.send(endpoint, &msg).await {
                    debug!(
                        "[{}] failed to send handshake response: {:?}",
                        self.label, e
                    );
                    return;
                }
                self.last_send = now;
                self.update_status(|status| {
                    status.endpoint = Some(endpoint);
                    status.rx_bytes += INIT_MSG_LENGTH as u64;
                    status.last_recv = Some(SystemTime::now());
                    status.tx_bytes += msg.len() as u64;
                    status.last_send = Some(SystemTime::now());
                    status.last_successful_handshake = Some(SystemTime::now());
                });
                debug!(
                    "[{}] received handshake initiation from {}; sent response",
                    self.label, endpoint
                );
            }
            PeerAction::RecvHandshakeResp(mut resp, endpoint) => {
                let rx_bytes = resp.len() as u64;
                match self
                    .machine
                    .handshake_response(&self.our_key, now, &mut resp, endpoint)
                {
                    Ok(retired) => {
                        self.retire_index(retired);
                        self.handshake = None;
                        self.session = Some(Session::new(true, now));
                        self.update_status(|status| {
                            status.endpoint = Some(endpoint);
                            status.rx_bytes += rx_bytes;
                            status.last_recv = Some(SystemTime::now());
                            status.last_successful_handshake = Some(SystemTime::now());
                        });
                        debug!("[{}] handshake complete; session established", self.label);
                        self.session_established(true).await;
                    }
                    // an invalid response is dropped; the pending handshake keeps
                    // its retransmit schedule
                    Err(e) => debug!(
                        "[{}] dropping invalid handshake response: {:?}",
                        self.label, e
                    ),
                }
            }
            PeerAction::RecvCookieReply(reply) => {
                match self.machine.cookie_reply(&reply, Tai64N::now()) {
                    Ok(()) => debug!("[{}] cookie accepted", self.label),
                    Err(e) => debug!("[{}] dropping invalid cookie reply: {:?}", self.label, e),
                }
            }
        }
    }

    fn stage(&mut self, payloads: &mut Vec<Vec<u8>>) {
        for payload in payloads.drain(..) {
            if self.staged.len() == MAX_STAGED_PACKETS {
                self.staged.pop_front();
            }
            self.staged.push_back(payload);
        }
    }

    async fn flush_staged(&mut self) {
        if self.staged.is_empty() {
            return;
        }
        let mut payloads: Vec<Vec<u8>> = self.staged.drain(..).collect();
        self.flush_sends(&mut payloads).await;
    }

    async fn flush_sends(&mut self, payloads: &mut Vec<Vec<u8>>) {
        if payloads.is_empty() {
            return;
        }
        let now = self.clock.now();
        let gso_segments = self.socket.max_gso_segments();
        let mut start = 0;
        let mut stalled = false;
        let mut sent = false;
        let mut encrypted_any = false;
        while start < payloads.len() {
            let segment_size = Transport::packet_len(payloads[start].len());
            let max_segments = max_batch_segments(gso_segments, segment_size);
            let mut end = start + 1;
            while end < payloads.len()
                && end - start < max_segments
                && Transport::packet_len(payloads[end].len()) == segment_size
            {
                end += 1;
            }
            let mut batch = vec![0u8; (end - start) * segment_size];
            let mut encrypted = 0;
            for (payload, buf) in payloads[start..end]
                .iter()
                .zip(batch.chunks_mut(segment_size))
            {
                match self.machine.encrypt(now, payload, buf) {
                    Ok(_) => encrypted += 1,
                    Err(_) => {
                        stalled = true;
                        break;
                    }
                }
            }
            if encrypted > 0 {
                encrypted_any = true;
                batch.truncate(encrypted * segment_size);
                let endpoint = self
                    .machine
                    .endpoint()
                    .expect("usable session has endpoint");
                match self
                    .socket
                    .send_segments(endpoint, &batch, segment_size)
                    .await
                {
                    Ok(()) => {
                        sent = true;
                        self.update_status(|status| {
                            status.tx_bytes += batch.len() as u64;
                            status.last_send = Some(SystemTime::now());
                        });
                    }
                    Err(e) => debug!("[{}] failed to send outbound packets: {:?}", self.label, e),
                }
            }
            start += encrypted;
            if stalled {
                break;
            }
        }
        if start < payloads.len() {
            self.session = None;
            payloads.drain(..start);
            self.stage(payloads);
            self.ensure_handshake().await;
            return;
        }
        payloads.clear();
        let mut rekey = encrypted_any && self.machine.rekey_due_to_messages();
        if sent {
            self.last_send = now;
            if let Some(session) = self.session.as_mut() {
                session.data_sent(now);
                rekey |= session.rekey_after_send(now);
            }
        }
        if rekey && self.handshake.is_none() {
            self.send_handshake(now).await;
        }
    }

    async fn send_keepalive(&mut self) {
        let now = self.clock.now();
        let mut msg = [0u8; Transport::packet_len(0)];
        let Ok(len) = self.machine.encrypt(now, &[], &mut msg) else {
            // keepalives don't revive an expired session
            self.session = None;
            return;
        };
        let message_rekey = self.machine.rekey_due_to_messages();
        let endpoint = self
            .machine
            .endpoint()
            .expect("usable session has endpoint");
        if let Some(session) = self.session.as_mut() {
            session.keepalive_sent();
        }
        let sent = match self.socket.send(endpoint, &msg[..len]).await {
            Ok(()) => {
                debug!("[{}] sent keepalive", self.label);
                self.last_send = now;
                self.update_status(|status| {
                    status.tx_bytes += len as u64;
                    status.last_send = Some(SystemTime::now());
                });
                true
            }
            Err(e) => {
                debug!("[{}] failed to send keepalive: {:?}", self.label, e);
                false
            }
        };
        let time_rekey = sent
            && self
                .session
                .as_ref()
                .is_some_and(|session| session.rekey_after_send(now));
        if message_rekey || time_rekey {
            self.ensure_handshake().await;
        }
    }

    fn persistent_keepalive_at(&self) -> Option<Timestamp> {
        self.persistent_keepalive
            .filter(|_| self.machine.endpoint().is_some())
            .map(|interval| self.last_send + interval)
    }

    async fn handshake_due(&mut self) {
        let Some(handshake) = self.handshake else {
            return;
        };
        let now = self.clock.now();
        if now.duration_since(handshake.first_sent) >= REKEY_ATTEMPT_TIME {
            debug!(
                "[{}] handshake abandoned after {:?}",
                self.label, REKEY_ATTEMPT_TIME
            );
            self.handshake = None;
            self.staged.clear();
            let abandoned = self.machine.abandon_handshake();
            self.retire_index(abandoned);
        } else {
            self.send_handshake(handshake.first_sent).await;
        }
    }

    fn session_expired(&mut self) {
        // the machine already refuses expired sessions; drop the timers
        debug!("[{}] session expired", self.label);
        self.session = None;
    }

    async fn new_handshake_due(&mut self) {
        if let Some(session) = self.session.as_mut() {
            session.new_handshake_at = None;
        }
        self.ensure_handshake().await;
    }

    async fn persistent_keepalive_due(&mut self) {
        let now = self.clock.now();
        self.last_send = now;
        if self.session.as_ref().is_some_and(|s| s.usable(now)) {
            self.send_keepalive().await;
        } else {
            // the handshake stands in for the keepalive: completing it
            // confirms the session with one
            self.ensure_handshake().await;
        }
    }

    async fn run(mut self, mut rx: Receiver<PeerAction>) {
        debug!("[{}] peer added", self.label);
        let mut actions = Vec::with_capacity(BATCH_SIZE);
        let mut payloads = Vec::with_capacity(BATCH_SIZE);
        loop {
            let handshake_at = self.handshake.map(|handshake| handshake.retry_at);
            let session = self.session.as_ref();
            let expires_at = session.map(|session| session.expires_at);
            let keepalive_at = session.and_then(|session| session.keepalive_at);
            let new_handshake_at = session.and_then(|session| session.new_handshake_at);
            let persistent_at = self.persistent_keepalive_at();
            select! {
                n = rx.recv_many(&mut actions, BATCH_SIZE) => {
                    if n == 0 {
                        debug!("[{}] peer removed", self.label);
                        return;
                    }
                    for action in actions.drain(..) {
                        match action {
                            PeerAction::SendData(payload) => payloads.push(payload),
                            action => {
                                self.flush_sends(&mut payloads).await;
                                self.handle_message(action).await;
                            }
                        }
                    }
                    self.flush_sends(&mut payloads).await;
                }
                () = self.clock.sleep_until(handshake_at), if handshake_at.is_some() => {
                    self.handshake_due().await;
                }
                () = self.clock.sleep_until(expires_at), if expires_at.is_some() => {
                    self.session_expired();
                }
                () = self.clock.sleep_until(keepalive_at), if keepalive_at.is_some() => {
                    self.send_keepalive().await;
                }
                () = self.clock.sleep_until(new_handshake_at), if new_handshake_at.is_some() => {
                    self.new_handshake_due().await;
                }
                () = self.clock.sleep_until(persistent_at), if persistent_at.is_some() => {
                    self.persistent_keepalive_due().await;
                }
            }
        }
    }
}

fn peer_label(key: &PublicKey) -> String {
    let b64 = key.to_string();
    format!("{}…{}", &b64[..4], &b64[39..43])
}

/// A single UDP sendmsg cannot carry more than 65,535 bytes even when GSO
/// splits it into multiple datagrams; Linux rejects larger sends with
/// EMSGSIZE, which quinn-udp does not treat as a cue to disable GSO.
fn max_batch_segments(gso_segments: usize, segment_size: usize) -> usize {
    gso_segments
        .min(crate::MAX_MESSAGE_SIZE / segment_size)
        .max(1)
}

/// Spawns the driver task for a registered peer and returns the watch that
/// reports its session readiness.
#[expect(clippy::too_many_arguments)]
pub(crate) fn spawn(
    our_key: Arc<PrivateKey>,
    public_key: PublicKey,
    config: &PeerConfig,
    control: mpsc::UnboundedSender<Control>,
    socket: Arc<UdpSocket>,
    status: Arc<RwLock<PeerStatus>>,
    actions: Receiver<PeerAction>,
    inbound_tx: Sender<Packet>,
) -> watch::Receiver<bool> {
    let (session_tx, session_rx) = watch::channel(false);
    let label = peer_label(&public_key);
    let mut machine = PeerState::new(public_key);
    if let Some(psk) = config.preshared_key.clone() {
        machine = machine.preshared_key(psk);
    }
    tokio::spawn(
        PeerActor {
            label,
            our_key,
            machine,
            clock: Clock::new(),
            control,
            persistent_keepalive: config.persistent_keepalive,
            last_send: Timestamp::default(),
            handshake: None,
            session: None,
            session_tx,
            staged: VecDeque::new(),
            socket,
            status,
            inbound_tx,
        }
        .run(actions),
    );
    session_rx
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::socket::UdpSocket;

    async fn test_actor(persistent_keepalive: Option<Duration>) -> PeerActor {
        let peer_key = PrivateKey::random().public_key();
        let (control, _control_rx) = mpsc::unbounded_channel();
        let (session_tx, _session_rx) = watch::channel(false);
        let (inbound_tx, _inbound_rx) = mpsc::channel(8);
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let status = Arc::new(RwLock::new(PeerStatus {
            public_key: peer_key.clone(),
            endpoint: None,
            tx_bytes: 0,
            rx_bytes: 0,
            last_send: None,
            last_recv: None,
            last_successful_handshake: None,
        }));
        PeerActor {
            label: "test".into(),
            our_key: Arc::new(PrivateKey::random()),
            machine: PeerState::new(peer_key),
            clock: Clock::new(),
            control,
            persistent_keepalive,
            last_send: Timestamp::default(),
            handshake: None,
            session: None,
            session_tx,
            staged: VecDeque::new(),
            socket,
            status,
            inbound_tx,
        }
    }

    // the persistent-keepalive deadline outlives sessions and handshakes: an
    // unreachable peer keeps re-initiating instead of sleeping forever
    #[tokio::test]
    async fn persistent_keepalive_survives_without_a_session() {
        let interval = Duration::from_secs(25);
        let mut actor = test_actor(Some(interval)).await;

        assert_eq!(actor.persistent_keepalive_at(), None);

        let endpoint = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        actor.machine.set_endpoint(endpoint.local_addr().unwrap());
        assert_eq!(
            actor.persistent_keepalive_at(),
            Some(Timestamp::default() + interval),
            "armed with no session and no handshake"
        );

        actor.persistent_keepalive_due().await;
        assert!(actor.handshake.is_some());
        assert!(actor.status.read().unwrap().tx_bytes > 0);
        assert!(actor.persistent_keepalive_at().unwrap() > actor.clock.now());
    }

    #[tokio::test(start_paused = true)]
    async fn handshake_abandoned_after_attempt_time() {
        let mut actor = test_actor(None).await;
        let endpoint = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        actor.machine.set_endpoint(endpoint.local_addr().unwrap());

        actor.ensure_handshake().await;
        let first = actor.handshake.expect("handshake in flight");
        assert!(first.retry_at >= Timestamp::default() + REKEY_TIMEOUT);
        assert!(first.retry_at < Timestamp::default() + REKEY_TIMEOUT + REKEY_TIMEOUT_JITTER_MAX);

        actor.handshake_due().await;
        assert_eq!(
            actor.handshake.expect("retransmitted").first_sent,
            first.first_sent
        );

        tokio::time::advance(REKEY_ATTEMPT_TIME).await;
        actor.handshake_due().await;
        assert!(actor.handshake.is_none(), "abandoned");
    }

    #[test]
    fn rekey_jitter_stays_within_the_spec_bound() {
        for _ in 0..100 {
            assert!(rekey_jitter() < REKEY_TIMEOUT_JITTER_MAX);
        }
    }

    #[test]
    fn an_idle_session_only_expires() {
        let now = Timestamp::default();
        let session = Session::new(true, now);
        assert_eq!(session.expires_at, now + REJECT_AFTER_TIME);
        assert_eq!(session.keepalive_at, None);
        assert_eq!(session.new_handshake_at, None);
        assert!(session.usable(now));
        assert!(!session.usable(now + REJECT_AFTER_TIME));
    }

    #[test]
    fn received_payload_owes_a_passive_keepalive() {
        let now = Timestamp::default();
        let mut session = Session::new(false, now);

        session.packet_received(now, false);
        assert_eq!(session.keepalive_at, None);

        session.packet_received(now, true);
        assert_eq!(session.keepalive_at, Some(now + KEEPALIVE_TIMEOUT));

        session.keepalive_sent();
        assert_eq!(session.keepalive_at, None);
    }

    #[test]
    fn unanswered_data_arms_a_new_handshake() {
        let now = Timestamp::default();
        let mut session = Session::new(true, now);
        let earliest = now + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT;

        session.data_sent(now);
        let deadline = session.new_handshake_at.expect("armed by data");
        assert!(deadline >= earliest && deadline < earliest + REKEY_TIMEOUT_JITTER_MAX);

        // further sends keep the original deadline
        session.data_sent(now + Duration::from_secs(1));
        assert_eq!(session.new_handshake_at, Some(deadline));

        // an authenticated reply disarms it
        session.packet_received(now + Duration::from_secs(2), false);
        assert_eq!(session.new_handshake_at, None);
    }

    #[test]
    fn keepalive_and_new_handshake_deadlines_are_exclusive() {
        let now = Timestamp::default();
        let mut session = Session::new(true, now);

        session.packet_received(now, true);
        assert_eq!(session.keepalive_at, Some(now + KEEPALIVE_TIMEOUT));
        session.data_sent(now);
        assert_eq!(session.keepalive_at, None);
        assert!(session.new_handshake_at.is_some());

        session.packet_received(now, true);
        assert_eq!(session.new_handshake_at, None);
        assert_eq!(session.keepalive_at, Some(now + KEEPALIVE_TIMEOUT));
    }

    #[test]
    fn initiator_rekeys_before_session_expiry() {
        let now = Timestamp::default();
        let initiator = Session::new(true, now);
        let responder = Session::new(false, now);

        let send_at = now + REKEY_AFTER_TIME;
        assert!(!initiator.rekey_after_send(now + (REKEY_AFTER_TIME - Duration::from_millis(1))));
        assert!(initiator.rekey_after_send(send_at));
        assert!(!responder.rekey_after_send(send_at));

        let recv_at = now + REKEY_AFTER_TIME_RECEIVING;
        assert!(
            !initiator
                .rekey_after_receive(now + (REKEY_AFTER_TIME_RECEIVING - Duration::from_millis(1)))
        );
        assert!(initiator.rekey_after_receive(recv_at));
        assert!(!responder.rekey_after_receive(recv_at));
    }

    // GSO batches must respect the 65,535-byte sendmsg limit, not just the
    // platform's segment count
    #[test]
    fn gso_batches_stay_under_the_udp_send_limit() {
        let mtu_sized = Transport::packet_len(1420);
        let limit = max_batch_segments(64, mtu_sized);
        assert!(limit * mtu_sized <= crate::MAX_MESSAGE_SIZE);
        assert!((limit + 1) * mtu_sized > crate::MAX_MESSAGE_SIZE);

        // small packets are bounded by the platform segment count
        assert_eq!(max_batch_segments(64, Transport::packet_len(0)), 64);

        // a maximum-size packet still forms a batch of one
        assert_eq!(max_batch_segments(64, crate::MAX_MESSAGE_SIZE), 1);
    }

    // without persistent keepalive, a peer with no session and no handshake
    // has nothing scheduled (it only reacts to traffic and commands)
    #[tokio::test]
    async fn idle_peer_has_no_deadline() {
        let mut actor = test_actor(None).await;
        let endpoint = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        actor.machine.set_endpoint(endpoint.local_addr().unwrap());
        assert_eq!(actor.persistent_keepalive_at(), None);
        assert!(actor.handshake.is_none());
        assert!(actor.session.is_none());
    }
}
