//! The per-peer driver: owns the sans-IO state machine, its liveness
//! schedule, and the staged-send queue.

use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{Arc, RwLock, Weak},
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
    time::{Instant, interval},
};
use tunstile_protocol::{
    PrivateKey, PublicKey, ReusableSecret, Tai64N,
    handshake::{Handshake, INIT_MSG_LENGTH, InitReceived, RESP_MSG_LENGTH},
    peer::{
        HandshakeValues, KEEPALIVE_TIMEOUT, Peer as PeerState, REJECT_AFTER_TIME, REKEY_AFTER_TIME,
        REKEY_ATTEMPT_TIME, REKEY_TIMEOUT,
    },
    time::Instant as Timestamp,
    transport::Transport,
};

use crate::{PeerConfig, PeerStatus, peer, router::RoutingTable, socket::UdpSocket};

const MAX_STAGED_PACKETS: usize = 128;
const PEER_INBOUND_QUEUE: usize = 1024;

// every liveness rule tolerates second-scale slop; 100ms keeps short
// keepalive intervals responsive
const TICK_INTERVAL: Duration = Duration::from_millis(100);

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
        Timestamp::from_millis(self.epoch.elapsed().as_millis() as u64)
    }
}

pub(crate) enum PeerAction {
    Connect(SocketAddr),
    SetConfig(PeerConfig),
    SendData(Vec<u8>),
    RecvData(Vec<u8>, u32, SocketAddr),
    RecvHandshakeInit(Handshake<InitReceived>, SocketAddr),
    RecvHandshakeResp(Vec<u8>, SocketAddr),
    RecvCookieReply(Vec<u8>),
}

#[derive(Clone, Copy)]
struct HandshakeTimers {
    first_sent: Timestamp,
    last_sent: Timestamp,
}

struct SessionTimers {
    initiator: bool,
    established: Timestamp,
    last_send: Timestamp,
    // passive keepalive
    keepalive_at: Option<Timestamp>,
    // first data send with no authenticated receive since
    unanswered_send: Option<Timestamp>,
}

impl SessionTimers {
    fn new(initiator: bool, now: Timestamp) -> Self {
        Self {
            initiator,
            established: now,
            last_send: now,
            keepalive_at: None,
            unanswered_send: None,
        }
    }
}

struct PeerActor {
    label: String,
    our_key: Arc<PrivateKey>,
    machine: PeerState,
    clock: Clock,

    // weak so dropping the Tunnel terminates the peer actors
    router: Weak<RoutingTable>,

    persistent_keepalive: Option<Duration>,
    handshake: Option<HandshakeTimers>,
    session: Option<SessionTimers>,

    session_tx: watch::Sender<bool>,
    staged: VecDeque<Vec<u8>>,

    socket: Arc<UdpSocket>,

    status: Arc<RwLock<PeerStatus>>,

    data_tx: Sender<Vec<u8>>,
}

impl PeerActor {
    fn update_status<F>(&self, mut func: F)
    where
        F: FnMut(&mut PeerStatus),
    {
        let mut status = self.status.write().unwrap();
        func(&mut status)
    }

    fn retire_index(&self, index: Option<u32>) {
        if let (Some(index), Some(router)) = (index, self.router.upgrade()) {
            router.retire_index(index);
        }
    }

    /// Sends a fresh handshake initiation. Retransmits pass the original
    /// `first_sent` so the abandonment window stays anchored.
    async fn send_handshake(&mut self, first_sent: Timestamp) {
        let Some(endpoint) = self.machine.endpoint() else {
            return;
        };
        let now = self.clock.now();
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
        if let Some(router) = self.router.upgrade() {
            router.bind_index(self.machine.peer_key(), index);
        }
        self.handshake = Some(HandshakeTimers {
            first_sent,
            last_sent: now,
        });
        if let Err(e) = self.socket.send(endpoint, &msg).await {
            debug!(
                "[{}] failed to send handshake initiation: {:?}",
                self.label, e
            );
            return;
        }
        debug!("[{}] sent handshake initiation to {}", self.label, endpoint);
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

    async fn set_config(&mut self, config: PeerConfig) {
        self.machine.set_preshared_key(config.preshared_key);
        self.persistent_keepalive = config.persistent_keepalive;
        if let Some(endpoint) = config.endpoint {
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
            PeerAction::SetConfig(config) => self.set_config(config).await,
            PeerAction::SendData(payload) => {
                let mut payloads = vec![payload];
                self.flush_sends(&mut payloads).await;
            }
            PeerAction::RecvData(mut data, receiver, endpoint) => {
                let rx_bytes = data.len() as u64;
                match self.machine.decrypt(now, receiver, &mut data, endpoint) {
                    Ok(recv) => {
                        let confirmed = recv.confirmed;
                        let unmapped = recv.unmapped;
                        let payload_range = recv.payload;
                        let payload = (!payload_range.is_empty()).then(|| {
                            debug_assert_eq!(payload_range.start, 0);
                            data.truncate(payload_range.end);
                            data
                        });
                        self.retire_index(unmapped);
                        self.update_status(|status| {
                            status.endpoint = Some(endpoint);
                            status.rx_bytes += rx_bytes;
                            status.last_recv = Some(SystemTime::now());
                        });
                        if confirmed {
                            debug!("[{}] session confirmed", self.label);
                            self.session = Some(SessionTimers::new(false, now));
                        }
                        if let Some(session) = self.session.as_mut() {
                            session.unanswered_send = None;
                            if payload.is_some() && session.keepalive_at.is_none() {
                                session.keepalive_at = Some(now + KEEPALIVE_TIMEOUT);
                            }
                        }
                        if let Some(payload) = payload {
                            // drop on a full queue rather than await: a slow or absent
                            // reader must not stall the actor's timers and handshakes
                            if let Err(mpsc::error::TrySendError::Full(_)) =
                                self.data_tx.try_send(payload)
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
                if let Some(router) = self.router.upgrade() {
                    router.bind_index(self.machine.peer_key(), index);
                }
                if let Err(e) = self.socket.send(endpoint, &msg).await {
                    debug!(
                        "[{}] failed to send handshake response: {:?}",
                        self.label, e
                    );
                    return;
                }
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
                        self.session = Some(SessionTimers::new(true, now));
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
        let max_segments = self.socket.max_gso_segments();
        let mut start = 0;
        let mut stalled = false;
        let mut sent = false;
        while start < payloads.len() {
            let segment_size = Transport::packet_len(payloads[start].len());
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
        let mut rekey = false;
        if sent && let Some(session) = self.session.as_mut() {
            session.last_send = now;
            session.keepalive_at = None;
            session.unanswered_send.get_or_insert(now);
            rekey =
                session.initiator && now.duration_since(session.established) >= REKEY_AFTER_TIME;
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
        let endpoint = self
            .machine
            .endpoint()
            .expect("usable session has endpoint");
        match self.socket.send(endpoint, &msg[..len]).await {
            Ok(()) => {
                debug!("[{}] sent keepalive", self.label);
                if let Some(session) = self.session.as_mut() {
                    session.last_send = now;
                    session.keepalive_at = None;
                }
                self.update_status(|status| {
                    status.tx_bytes += len as u64;
                    status.last_send = Some(SystemTime::now());
                });
            }
            Err(e) => debug!("[{}] failed to send keepalive: {:?}", self.label, e),
        }
    }

    async fn tick(&mut self) {
        let now = self.clock.now();
        if self
            .session
            .as_ref()
            .is_some_and(|s| now.duration_since(s.established) >= REJECT_AFTER_TIME)
        {
            // the machine already refuses expired sessions; drop our timers
            debug!("[{}] session expired", self.label);
            self.session = None;
        }
        if let Some(handshake) = self.handshake
            && now >= handshake.last_sent + REKEY_TIMEOUT
        {
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
        let mut keepalive = false;
        let mut silent = false;
        if let Some(session) = self.session.as_mut() {
            if session.keepalive_at.is_some_and(|t| now >= t) {
                session.keepalive_at = None;
                keepalive = true;
            }
            if self
                .persistent_keepalive
                .is_some_and(|interval| now >= session.last_send + interval)
            {
                keepalive = true;
            }
            if session
                .unanswered_send
                .is_some_and(|t| now >= t + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT)
            {
                session.unanswered_send = None;
                silent = true;
            }
        }
        if keepalive {
            self.send_keepalive().await;
        }
        if silent {
            self.ensure_handshake().await;
        }
    }

    async fn run(mut self, mut rx: Receiver<PeerAction>) {
        debug!("[{}] peer added", self.label);
        let mut actions = Vec::with_capacity(BATCH_SIZE);
        let mut payloads = Vec::with_capacity(BATCH_SIZE);
        let mut tick = interval(TICK_INTERVAL);
        loop {
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
                _ = tick.tick() => self.tick().await,
            }
        }
    }
}

fn peer_label(key: &PublicKey) -> String {
    let b64 = key.to_string();
    format!("{}…{}", &b64[..4], &b64[39..43])
}

/// Spawns the driver task for a registered peer and returns its handle.
pub(crate) fn spawn(
    our_key: Arc<PrivateKey>,
    public_key: PublicKey,
    config: &PeerConfig,
    router: Weak<RoutingTable>,
    socket: Arc<UdpSocket>,
    status: Arc<RwLock<PeerStatus>>,
    actions: Receiver<PeerAction>,
) -> peer::Peer {
    let (data_tx, data_rx) = mpsc::channel(PEER_INBOUND_QUEUE);
    let (session_tx, session_rx) = watch::channel(false);
    let label = peer_label(&public_key);
    let peer_key = public_key.clone();
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
            router: router.clone(),
            persistent_keepalive: config.persistent_keepalive,
            handshake: None,
            session: None,
            session_tx,
            staged: VecDeque::new(),
            socket,
            status: status.clone(),
            data_tx,
        }
        .run(actions),
    );
    peer::Peer::new(peer_key, router, status, session_rx, data_rx)
}
