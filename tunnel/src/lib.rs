use std::{
    collections::{HashMap, VecDeque},
    io::{self, IoSliceMut},
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, RwLock, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, SystemTime},
};

pub use bytes::Bytes;
use bytes::BytesMut;
use log::debug;
use quinn_udp::{BATCH_SIZE, RecvMeta};
pub use spacetun_protocol::{KeyParseError, PrivateKey, PublicKey};
use spacetun_protocol::{
    MessageHeader, ReusableSecret, Tai64N,
    cookies::{COOKIE_REPLY_LENGTH, Generator, Verifier},
    handshake::{self, Handshake, INIT_MSG_LENGTH, InitReceived, InitSent},
    transport::{ReplayFilter, Transport},
};
use thiserror::Error;
use tokio::{
    select, spawn,
    sync::{
        mpsc::{self, Receiver, Sender},
        watch,
    },
    task::JoinHandle,
    time::{Instant, sleep_until},
};

mod socket;
use socket::UdpSocket;

const MAX_MESSAGE_SIZE: usize = 65535;
const MAX_STAGED_PACKETS: usize = 128;
const PEER_INBOUND_QUEUE: usize = 1024;

// above this inbound-handshake rate we demand a cookie before spending CPU
const MAX_HANDSHAKES_PER_SECOND: u32 = 25;
const COOKIE_SECRET_ROTATION: Duration = Duration::from_secs(120);

const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SendError {
    #[error("tunnel closed")]
    Closed,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegisterError {
    #[error("peer already registered")]
    AlreadyRegistered,
}

fn peer_label(key: &PublicKey) -> String {
    let b64 = key.to_string();
    format!("{}…{}", &b64[..4], &b64[39..43])
}

#[derive(Debug, Clone)]
pub struct PeerConfig {
    public_key: PublicKey,
    endpoint: Option<SocketAddr>,
    preshared_key: Option<[u8; 32]>,
    persistent_keepalive: Option<Duration>,
}

impl PeerConfig {
    /// A config for the peer with the given public key and no other options.
    pub fn new(public_key: PublicKey) -> Self {
        Self {
            public_key,
            endpoint: None,
            preshared_key: None,
            persistent_keepalive: None,
        }
    }

    /// Sets the peer's initial endpoint.
    pub fn endpoint(mut self, endpoint: SocketAddr) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    /// Sets the optional pre-shared key.
    pub fn preshared_key(mut self, preshared_key: [u8; 32]) -> Self {
        self.preshared_key = Some(preshared_key);
        self
    }

    /// Sets the persistent keepalive interval.
    pub fn persistent_keepalive(mut self, interval: Duration) -> Self {
        self.persistent_keepalive = Some(interval);
        self
    }
}

enum PeerAction {
    Connect(SocketAddr),
    SendData(Bytes),
    RecvData(Vec<u8>, u32, SocketAddr),
    RecvHandshakeInit(Handshake<InitReceived>, SocketAddr),
    RecvHandshakeResp(Vec<u8>, SocketAddr),
    RecvCookieReply(Vec<u8>),
}

#[derive(Clone, Debug)]
pub struct PeerStatus {
    pub public_key: PublicKey,
    pub endpoint: Option<SocketAddr>,

    pub tx_bytes: u64,
    pub rx_bytes: u64,

    pub last_send: Option<SystemTime>,
    pub last_recv: Option<SystemTime>,
    pub last_successful_handshake: Option<SystemTime>,
}

struct PendingHandshake {
    state: Handshake<InitSent>,
    our_index: u32,
    // mac1 of the sent init; the AAD for decrypting a cookie reply to it
    sent_mac1: [u8; 16],
    first_sent: Instant,
    last_sent: Instant,
}

struct Session {
    transport: Arc<Transport>,
    initiator: bool,
    established: Instant,
    last_send: Instant,
    replay: ReplayFilter,

    // passive keepalive owed to the peer
    keepalive_at: Option<Instant>,
    // first data send with no authenticated receive since
    unanswered_send: Option<Instant>,
}

struct PeerActor {
    our_key: PrivateKey,
    peer_key: PublicKey,
    label: String,
    endpoint: Option<SocketAddr>,

    // weak so dropping the Tunnel terminates the peer actors
    router: Weak<RoutingTable>,

    // adds mac1/mac2 to our handshakes and consumes cookie replies from the peer
    cookie_generator: Generator,

    preshared_key: Option<[u8; 32]>,
    persistent_keepalive: Option<Duration>,

    pending_handshake: Option<PendingHandshake>,
    // send session; initiator-established sessions land here directly
    current: Option<Session>,
    // responder-established session awaiting its first authenticated packet
    next: Option<Session>,
    // receive-only grace for packets in flight across a rekey
    previous: Option<Session>,
    session_tx: watch::Sender<bool>,
    staged: VecDeque<Bytes>,

    socket: Arc<UdpSocket>,

    status: Arc<RwLock<PeerStatus>>,

    data_tx: Sender<Bytes>,
}

impl PeerActor {
    fn new_session(transport: Transport, initiator: bool) -> Session {
        let now = Instant::now();
        Session {
            transport: Arc::new(transport),
            initiator,
            established: now,
            last_send: now,
            replay: ReplayFilter::new(),
            keepalive_at: None,
            unanswered_send: None,
        }
    }

    fn retire_session(&self, session: Session) {
        if let Some(router) = self.router.upgrade() {
            router.retire_index(session.transport.our_index());
        }
    }

    /// Callers signal `session_tx` once the adopted session is usable.
    fn adopt_current(&mut self, session: Session, endpoint: SocketAddr) {
        let old = std::mem::replace(&mut self.previous, self.current.take());
        if let Some(old) = old {
            self.retire_session(old);
        }
        self.current = Some(session);
        self.endpoint = Some(endpoint);
    }

    fn update_status<F>(&self, mut func: F)
    where
        F: FnMut(&mut PeerStatus),
    {
        let mut status = self.status.write().unwrap();
        func(&mut status)
    }

    async fn handle_message(&mut self, action: PeerAction) {
        match action {
            PeerAction::Connect(endpoint) => {
                self.endpoint = Some(endpoint);
                self.ensure_handshake(Instant::now()).await;
            }
            PeerAction::SendData(payload) => {
                let mut payloads = vec![payload];
                self.flush_sends(&mut payloads).await;
            }
            PeerAction::RecvData(mut data, receiver, endpoint) => {
                let now = Instant::now();
                let matches = |s: &Option<Session>| {
                    s.as_ref()
                        .is_some_and(|s| s.transport.our_index() == receiver)
                };
                let (session, unconfirmed) = if matches(&self.next) {
                    (self.next.as_mut().unwrap(), true)
                } else if matches(&self.current) {
                    (self.current.as_mut().unwrap(), false)
                } else if matches(&self.previous) {
                    (self.previous.as_mut().unwrap(), false)
                } else {
                    return;
                };
                if now.duration_since(session.established) >= REJECT_AFTER_TIME {
                    return;
                }
                let transport = session.transport.clone();
                let rx_bytes = data.len() as u64;
                let (counter, payload) = match transport.receive(&mut data) {
                    Ok(decrypted) => decrypted,
                    Err(e) => {
                        debug!("[{}] failed to decrypt inbound packet: {:?}", self.label, e);
                        return;
                    }
                };
                if !session.replay.validate(counter) {
                    debug!(
                        "[{}] dropping replayed packet: counter {counter}",
                        self.label
                    );
                    return;
                }
                let payload = (!payload.is_empty()).then(|| Bytes::copy_from_slice(payload));

                self.endpoint = Some(endpoint);
                self.update_status(|status| {
                    status.endpoint = Some(endpoint);
                    status.rx_bytes += rx_bytes;
                    status.last_recv = Some(SystemTime::now());
                });
                if self.endpoint != Some(endpoint) {
                    debug!("[{}] endpoint updated to {}", self.label, endpoint);
                }
                if unconfirmed {
                    debug!("[{}] session confirmed", self.label);
                    let session = self.next.take().unwrap();
                    self.adopt_current(session, endpoint);
                    self.session_tx.send_replace(true);
                }
                if let Some(current) = self.current.as_mut() {
                    current.unanswered_send = None;
                    if payload.is_some() && current.keepalive_at.is_none() {
                        current.keepalive_at = Some(now + KEEPALIVE_TIMEOUT);
                    }
                }
                if let Some(payload) = payload {
                    // drop on a full queue rather than await: a slow or absent
                    // reader must not stall the actor's timers and handshakes
                    if let Err(mpsc::error::TrySendError::Full(_)) = self.data_tx.try_send(payload)
                    {
                        debug!(
                            "[{}] dropping inbound packet: receive queue full",
                            self.label
                        );
                    }
                }
                if unconfirmed {
                    self.flush_staged().await;
                }
            }
            PeerAction::RecvHandshakeInit(handshake, endpoint) => {
                let mut msg = BytesMut::zeroed(handshake::RESP_MSG_LENGTH);
                let ephemeral_secret = ReusableSecret::random();
                let timestamp = Tai64N::now();
                let our_index = rand::random();
                let new_transport = handshake
                    .respond(
                        our_index,
                        ephemeral_secret,
                        self.preshared_key,
                        timestamp,
                        &self.cookie_generator,
                        &mut msg,
                    )
                    .finish();
                if let Err(e) = self.socket.send(endpoint, &msg).await {
                    debug!(
                        "[{}] failed to send handshake response: {:?}",
                        self.label, e
                    );
                    return;
                }
                let Some(router) = self.router.upgrade() else {
                    return;
                };
                router.bind_index(&self.peer_key, our_index);
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
                let session = Self::new_session(new_transport, false);
                if let Some(old) = self.next.replace(session) {
                    self.retire_session(old);
                }
                self.endpoint = Some(endpoint);
            }
            PeerAction::RecvHandshakeResp(mut resp, endpoint) => {
                let rx_bytes = resp.len() as u64;
                let Some(pending) = self.pending_handshake.as_ref() else {
                    debug!("[{}] dropping unexpected handshake response", self.label);
                    return;
                };
                match pending
                    .state
                    .clone()
                    .response_received(self.preshared_key, &mut resp)
                {
                    Ok(established) => {
                        self.pending_handshake = None;
                        self.update_status(|status| {
                            status.endpoint = Some(endpoint);
                            status.rx_bytes += rx_bytes;
                            status.last_recv = Some(SystemTime::now());
                            status.last_successful_handshake = Some(SystemTime::now());
                        });
                        debug!("[{}] handshake complete; session established", self.label);
                        let had_staged = !self.staged.is_empty();
                        self.adopt_current(Self::new_session(established.finish(), true), endpoint);
                        self.flush_staged().await;
                        if !had_staged {
                            // confirm the session to the responder
                            self.send_keepalive().await;
                        }
                        self.session_tx.send_replace(true);
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
                let Some(pending) = self.pending_handshake.as_ref() else {
                    debug!("[{}] dropping unexpected cookie reply", self.label);
                    return;
                };
                let sent_mac1 = pending.sent_mac1;
                let first_sent = pending.first_sent;
                match self
                    .cookie_generator
                    .process_cookie_reply(&reply, &sent_mac1, &Tai64N::now())
                {
                    // resend now so the retransmit carries a valid mac2
                    Ok(()) => {
                        debug!("[{}] cookie accepted; retransmitting handshake", self.label);
                        self.start_handshake(Instant::now(), first_sent).await;
                    }
                    Err(e) => debug!("[{}] dropping invalid cookie reply: {:?}", self.label, e),
                }
            }
        }
    }

    async fn start_handshake(&mut self, now: Instant, first_sent: Instant) {
        let (Some(endpoint), Some(router)) = (self.endpoint, self.router.upgrade()) else {
            return;
        };
        let our_index = rand::random();
        let ephemeral_secret = ReusableSecret::random();
        let timestamp = Tai64N::now();
        let mut msg = vec![0u8; handshake::INIT_MSG_LENGTH];
        let state = Handshake::initiate(
            self.our_key.clone(),
            self.peer_key,
            our_index,
            ephemeral_secret,
            timestamp,
            &self.cookie_generator,
            &mut msg,
        );
        let mut sent_mac1 = [0u8; 16];
        let mac1_offset = handshake::INIT_MSG_LENGTH - 32;
        sent_mac1.copy_from_slice(&msg[mac1_offset..mac1_offset + 16]);
        if let Some(old) = self.pending_handshake.replace(PendingHandshake {
            state,
            our_index,
            sent_mac1,
            first_sent,
            last_sent: now,
        }) {
            router.retire_index(old.our_index);
        }
        router.bind_index(&self.peer_key, our_index);
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

    async fn ensure_handshake(&mut self, now: Instant) {
        if self.pending_handshake.is_none() {
            self.start_handshake(now, now).await;
        }
    }

    fn stage(&mut self, payloads: &mut Vec<Bytes>) {
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
        let mut payloads: Vec<Bytes> = self.staged.drain(..).collect();
        self.flush_sends(&mut payloads).await;
    }

    async fn flush_sends(&mut self, payloads: &mut Vec<Bytes>) {
        if payloads.is_empty() {
            return;
        }
        let now = Instant::now();
        let usable = match (self.endpoint, self.current.as_ref()) {
            (Some(endpoint), Some(session))
                if now.duration_since(session.established) < REJECT_AFTER_TIME =>
            {
                Some((
                    endpoint,
                    session.transport.clone(),
                    session.initiator,
                    session.established,
                ))
            }
            _ => None,
        };
        let Some((endpoint, transport, initiator, established)) = usable else {
            self.stage(payloads);
            self.ensure_handshake(now).await;
            return;
        };
        let max_segments = self.socket.max_gso_segments();
        let mut sent = false;
        let mut start = 0;
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
            for (payload, buf) in payloads[start..end]
                .iter()
                .zip(batch.chunks_mut(segment_size))
            {
                transport.send(payload, buf);
            }
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
            start = end;
        }
        payloads.clear();
        if sent && let Some(session) = self.current.as_mut() {
            session.last_send = now;
            session.keepalive_at = None;
            session.unanswered_send.get_or_insert(now);
        }
        if initiator
            && now.duration_since(established) >= REKEY_AFTER_TIME
            && self.pending_handshake.is_none()
        {
            self.start_handshake(now, now).await;
        }
    }

    async fn send_keepalive(&mut self) {
        let (Some(endpoint), Some(session)) = (self.endpoint, self.current.as_ref()) else {
            return;
        };
        let transport = session.transport.clone();
        let mut msg = vec![0u8; Transport::packet_len(0)];
        transport.send(&[], &mut msg);
        if let Err(e) = self.socket.send(endpoint, &msg).await {
            debug!("[{}] failed to send keepalive: {:?}", self.label, e);
            return;
        }
        debug!("[{}] sent keepalive", self.label);
        if let Some(session) = self.current.as_mut() {
            session.last_send = Instant::now();
            session.keepalive_at = None;
        }
        self.update_status(|status| {
            status.tx_bytes += msg.len() as u64;
            status.last_send = Some(SystemTime::now());
        });
    }

    fn next_deadline(&self) -> Option<Instant> {
        let retransmit = self
            .pending_handshake
            .as_ref()
            .map(|pending| pending.last_sent + REKEY_TIMEOUT);
        let (keepalive, silence, persistent) = self
            .current
            .as_ref()
            .map(|session| {
                (
                    session.keepalive_at,
                    session
                        .unanswered_send
                        .map(|t| t + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT),
                    self.persistent_keepalive
                        .map(|interval| session.last_send + interval),
                )
            })
            .unwrap_or((None, None, None));
        let expiry = [&self.previous, &self.current, &self.next]
            .into_iter()
            .filter_map(|s| s.as_ref().map(|s| s.established + REJECT_AFTER_TIME))
            .min();
        [retransmit, keepalive, silence, persistent, expiry]
            .into_iter()
            .flatten()
            .min()
    }

    async fn tick(&mut self) {
        let now = Instant::now();
        let router = self.router.upgrade();
        for slot in [&mut self.previous, &mut self.current, &mut self.next] {
            if slot
                .as_ref()
                .is_some_and(|s| now.duration_since(s.established) >= REJECT_AFTER_TIME)
                && let (Some(session), Some(router)) = (slot.take(), router.as_ref())
            {
                debug!("[{}] session expired", self.label);
                router.retire_index(session.transport.our_index());
            }
        }
        if let Some(pending) = &self.pending_handshake
            && now >= pending.last_sent + REKEY_TIMEOUT
        {
            if now.duration_since(pending.first_sent) >= REKEY_ATTEMPT_TIME {
                debug!(
                    "[{}] handshake abandoned after {:?}",
                    self.label, REKEY_ATTEMPT_TIME
                );
                let our_index = pending.our_index;
                self.pending_handshake = None;
                self.staged.clear();
                if let Some(router) = self.router.upgrade() {
                    router.retire_index(our_index);
                }
            } else {
                let first_sent = pending.first_sent;
                self.start_handshake(now, first_sent).await;
            }
        }
        let mut keepalive = false;
        let mut silent = false;
        if let Some(session) = self.current.as_mut() {
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
            self.ensure_handshake(now).await;
        }
    }

    async fn run(mut self, mut rx: Receiver<PeerAction>) {
        debug!("[{}] peer added", self.label);
        let mut actions = Vec::with_capacity(BATCH_SIZE);
        let mut payloads = Vec::with_capacity(BATCH_SIZE);
        loop {
            let deadline = self.next_deadline();
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
                _ = async {
                    match deadline {
                        Some(deadline) => sleep_until(deadline).await,
                        None => std::future::pending().await,
                    }
                } => self.tick().await,
            }
        }
    }
}

struct PeerEntry {
    actions: mpsc::Sender<PeerAction>,
    status: Arc<RwLock<PeerStatus>>,
}

struct RoutingTable {
    peer_indices: RwLock<HashMap<u32, mpsc::Sender<PeerAction>>>,
    peers: RwLock<HashMap<PublicKey, PeerEntry>>,
}

impl RoutingTable {
    fn new() -> Self {
        Self {
            peer_indices: RwLock::new(HashMap::new()),
            peers: RwLock::new(HashMap::new()),
        }
    }

    fn bind_index(&self, peer_key: &PublicKey, index: u32) -> bool {
        let Some(sender) = self.peer_key_sender(peer_key) else {
            return false;
        };
        self.peer_indices.write().unwrap().insert(index, sender);
        true
    }

    fn retire_index(&self, index: u32) {
        self.peer_indices.write().unwrap().remove(&index);
    }

    fn remove_peer(&self, peer_key: &PublicKey) {
        let Some(entry) = self.peers.write().unwrap().remove(peer_key) else {
            return;
        };
        self.peer_indices
            .write()
            .unwrap()
            .retain(|_, s| !s.same_channel(&entry.actions));
    }

    fn register_peer(
        &self,
        peer_key: PublicKey,
    ) -> Option<(mpsc::Receiver<PeerAction>, Arc<RwLock<PeerStatus>>)> {
        let mut peers = self.peers.write().unwrap();
        if peers.contains_key(&peer_key) {
            return None;
        }
        let (tx, rx) = mpsc::channel(1024);
        let status = Arc::new(RwLock::new(PeerStatus {
            public_key: peer_key,
            endpoint: None,
            tx_bytes: 0,
            rx_bytes: 0,
            last_send: None,
            last_recv: None,
            last_successful_handshake: None,
        }));
        peers.insert(
            peer_key,
            PeerEntry {
                actions: tx,
                status: status.clone(),
            },
        );
        Some((rx, status))
    }

    fn peer_key_sender(&self, public_key: &PublicKey) -> Option<Sender<PeerAction>> {
        self.peers
            .read()
            .unwrap()
            .get(public_key)
            .map(|entry| entry.actions.clone())
    }

    fn peer_status(&self, public_key: &PublicKey) -> Option<PeerStatus> {
        self.peers
            .read()
            .unwrap()
            .get(public_key)
            .map(|entry| entry.status.read().unwrap().clone())
    }

    fn peer_statuses(&self) -> Vec<PeerStatus> {
        self.peers
            .read()
            .unwrap()
            .values()
            .map(|entry| entry.status.read().unwrap().clone())
            .collect()
    }

    fn peer_index_sender(&self, index: u32) -> Option<Sender<PeerAction>> {
        self.peer_indices.read().unwrap().get(&index).cloned()
    }

    async fn connect(&self, public_key: &PublicKey, endpoint: SocketAddr) -> Result<(), SendError> {
        let sender = self.peer_key_sender(public_key).ok_or(SendError::Closed)?;
        sender
            .send(PeerAction::Connect(endpoint))
            .await
            .map_err(|_| SendError::Closed)
    }

    async fn send_data(&self, public_key: &PublicKey, packet: Bytes) -> Result<(), SendError> {
        let sender = self.peer_key_sender(public_key).ok_or(SendError::Closed)?;
        sender
            .send(PeerAction::SendData(packet))
            .await
            .map_err(|_| SendError::Closed)
    }

    async fn recv_handshake_init(
        &self,
        endpoint: SocketAddr,
        handshake: Handshake<InitReceived>,
    ) -> bool {
        let peer_key = handshake.peer_key();
        if let Some(sender) = self.peer_key_sender(&peer_key) {
            let _ = sender
                .send(PeerAction::RecvHandshakeInit(handshake, endpoint))
                .await;
            return true;
        }
        false
    }

    async fn recv_handshake_resp(
        &self,
        endpoint: SocketAddr,
        peer_index: u32,
        packet: Vec<u8>,
    ) -> bool {
        if let Some(sender) = self.peer_index_sender(peer_index) {
            let _ = sender
                .send(PeerAction::RecvHandshakeResp(packet, endpoint))
                .await;
            return true;
        }
        false
    }

    async fn recv_data(&self, endpoint: SocketAddr, peer_index: u32, packet: Vec<u8>) -> bool {
        if let Some(sender) = self.peer_index_sender(peer_index) {
            let _ = sender
                .send(PeerAction::RecvData(packet, peer_index, endpoint))
                .await;
            return true;
        }
        false
    }

    async fn recv_cookie_reply(&self, peer_index: u32, packet: Vec<u8>) -> bool {
        if let Some(sender) = self.peer_index_sender(peer_index) {
            let _ = sender.send(PeerAction::RecvCookieReply(packet)).await;
            return true;
        }
        false
    }
}

/// A handle to a registered peer: the owned receive half of its inbound
/// queue plus its send and status operations. The handle is the
/// registration — dropping it removes the peer from the tunnel.
#[must_use = "dropping the Peer unregisters it from the tunnel"]
pub struct Peer {
    public_key: PublicKey,
    router: Weak<RoutingTable>,
    status: Arc<RwLock<PeerStatus>>,
    session_rx: watch::Receiver<bool>,
    data_rx: mpsc::Receiver<Bytes>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        if let Some(router) = self.router.upgrade() {
            router.remove_peer(&self.public_key);
        }
    }
}

impl Peer {
    /// This peer's public key.
    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    /// Current status snapshot for this peer.
    pub fn status(&self) -> PeerStatus {
        self.status.read().unwrap().clone()
    }

    /// Receives the next decrypted payload from this peer. Returns `None`
    /// once the peer is removed or the tunnel is dropped.
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.data_rx.recv().await
    }

    /// Sends a payload to this peer, staging it if no session is established yet.
    pub async fn send(&self, payload: impl Into<Bytes>) -> Result<(), SendError> {
        let router = self.router.upgrade().ok_or(SendError::Closed)?;
        router.send_data(&self.public_key, payload.into()).await
    }

    /// Updates the peer's endpoint and initiates a handshake if none is in
    /// flight. Use when the peer's address changes, e.g. after a DNS re-resolve.
    pub async fn connect(&self, endpoint: SocketAddr) -> Result<(), SendError> {
        let router = self.router.upgrade().ok_or(SendError::Closed)?;
        router.connect(&self.public_key, endpoint).await
    }

    /// Resolves once a session is established with the peer. Errors if the
    /// tunnel is dropped first.
    pub async fn ready(&self) -> Result<(), SendError> {
        self.session_rx
            .clone()
            .wait_for(|ready| *ready)
            .await
            .map(|_| ())
            .map_err(|_| SendError::Closed)
    }

    /// Returns a cloneable send handle. Unlike the `Peer`, it does not own the
    /// registration: dropping every sender does not remove the peer.
    pub fn sender(&self) -> PeerSender {
        PeerSender {
            public_key: self.public_key,
            router: self.router.clone(),
        }
    }
}

/// A cloneable handle for sending to a peer, decoupled from its inbound
/// queue so many callers can share the send path.
#[derive(Clone)]
pub struct PeerSender {
    public_key: PublicKey,
    router: Weak<RoutingTable>,
}

impl PeerSender {
    /// The peer's public key.
    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    /// Sends a payload to the peer, staging it if no session is established yet.
    pub async fn send(&self, payload: impl Into<Bytes>) -> Result<(), SendError> {
        let router = self.router.upgrade().ok_or(SendError::Closed)?;
        router.send_data(&self.public_key, payload.into()).await
    }

    /// Updates the peer's endpoint and initiates a handshake if none is pending.
    pub async fn connect(&self, endpoint: SocketAddr) -> Result<(), SendError> {
        let router = self.router.upgrade().ok_or(SendError::Closed)?;
        router.connect(&self.public_key, endpoint).await
    }

    /// Current status snapshot, or `None` if the peer is no longer registered.
    pub fn status(&self) -> Option<PeerStatus> {
        self.router.upgrade()?.peer_status(&self.public_key)
    }
}

impl futures_core::Stream for Peer {
    type Item = Bytes;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().data_rx.poll_recv(cx)
    }
}

enum HandshakeDecision {
    Process,
    Drop,
    Cookie([u8; COOKIE_REPLY_LENGTH]),
}

// Responder-side DoS mitigation, owned by the single read loop: cheap mac1
// rejection always, and a cookie challenge (mac2) once the inbound handshake
// rate crosses a threshold.
struct LoadGuard {
    verifier: Verifier,
    secret: [u8; 32],
    secret_rotated: Instant,
    window_start: Instant,
    handshakes: u32,
    force: Arc<AtomicBool>,
}

impl LoadGuard {
    fn new(our_public: PublicKey, force: Arc<AtomicBool>) -> Self {
        let now = Instant::now();
        Self {
            verifier: Verifier::new(our_public),
            secret: rand::random(),
            secret_rotated: now,
            window_start: now,
            handshakes: 0,
            force,
        }
    }

    fn check(&mut self, msg: &[u8], source: SocketAddr) -> HandshakeDecision {
        if msg.len() < 32 || !self.verifier.verify_mac_1(msg) {
            return HandshakeDecision::Drop;
        }
        let now = Instant::now();
        if now.duration_since(self.secret_rotated) >= COOKIE_SECRET_ROTATION {
            self.secret = rand::random();
            self.secret_rotated = now;
        }
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.window_start = now;
            self.handshakes = 0;
        }
        self.handshakes += 1;

        let under_load =
            self.force.load(Ordering::Relaxed) || self.handshakes > MAX_HANDSHAKES_PER_SECOND;
        if !under_load {
            return HandshakeDecision::Process;
        }
        let source = source_bytes(source);
        if self.verifier.verify_mac_2(msg, &source, &self.secret) {
            return HandshakeDecision::Process;
        }
        let mut reply = [0u8; COOKIE_REPLY_LENGTH];
        self.verifier
            .write_cookie_reply(msg, &source, &self.secret, rand::random(), &mut reply);
        HandshakeDecision::Cookie(reply)
    }
}

fn source_bytes(addr: SocketAddr) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(18);
    match addr.ip() {
        IpAddr::V4(ip) => bytes.extend_from_slice(&ip.octets()),
        IpAddr::V6(ip) => bytes.extend_from_slice(&ip.octets()),
    }
    bytes.extend_from_slice(&addr.port().to_be_bytes());
    bytes
}

pub struct Tunnel {
    our_key: PrivateKey,
    socket: Arc<UdpSocket>,
    router: Arc<RoutingTable>,
    // only the read loop's clone is read in production; the tunnel keeps a
    // handle solely so tests can force the under-load path
    #[cfg(test)]
    under_load: Arc<AtomicBool>,
    read_task: JoinHandle<()>,
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.read_task.abort();
    }
}

impl Tunnel {
    async fn read_loop(
        our_private: PrivateKey,
        socket: Arc<UdpSocket>,
        router: Arc<RoutingTable>,
        under_load: Arc<AtomicBool>,
    ) {
        let mut guard = LoadGuard::new(our_private.public_key(), under_load);
        let mut bufs = vec![vec![0u8; MAX_MESSAGE_SIZE]; BATCH_SIZE];
        let mut metas = [RecvMeta::default(); BATCH_SIZE];
        loop {
            let mut slices: Vec<IoSliceMut> = bufs.iter_mut().map(|b| IoSliceMut::new(b)).collect();
            let n = match socket.recv(&mut slices, &mut metas).await {
                Ok(n) => n,
                Err(e) => {
                    debug!("failed to receive packets: {:?}", e);
                    continue;
                }
            };
            drop(slices);
            for (buf, meta) in bufs.iter_mut().zip(metas.iter()).take(n) {
                let mut offset = 0;
                while offset < meta.len {
                    let len = meta.stride.min(meta.len - offset);
                    if len == 0 {
                        break;
                    }
                    let segment = &mut buf[offset..offset + len];
                    offset += len;
                    let header = match MessageHeader::try_from(&*segment) {
                        Ok(header) => header,
                        Err(e) => {
                            debug!("dropping invalid packet from {}: {:?}", meta.addr, e);
                            continue;
                        }
                    };
                    if matches!(
                        header,
                        MessageHeader::HandshakeInit | MessageHeader::HandshakeResponse { .. }
                    ) {
                        match guard.check(segment, meta.addr) {
                            HandshakeDecision::Process => {}
                            HandshakeDecision::Drop => {
                                debug!("dropping handshake from {} (mac1)", meta.addr);
                                continue;
                            }
                            HandshakeDecision::Cookie(reply) => {
                                let _ = socket.send(meta.addr, &reply).await;
                                continue;
                            }
                        }
                    }
                    match header {
                        MessageHeader::HandshakeInit => {
                            match Handshake::receive(our_private.clone(), segment) {
                                Ok(handshake) => {
                                    let _ = router.recv_handshake_init(meta.addr, handshake).await;
                                }
                                Err(e) => {
                                    debug!(
                                        "dropping invalid handshake init from {}: {:?}",
                                        meta.addr, e
                                    );
                                }
                            }
                        }
                        MessageHeader::HandshakeResponse { receiver } => {
                            let _ = router
                                .recv_handshake_resp(meta.addr, receiver, segment.to_vec())
                                .await;
                        }
                        MessageHeader::Data { receiver } => {
                            let _ = router
                                .recv_data(meta.addr, receiver, segment.to_vec())
                                .await;
                        }
                        MessageHeader::CookieReply { receiver } => {
                            let _ = router.recv_cookie_reply(receiver, segment.to_vec()).await;
                        }
                    };
                }
            }
        }
    }

    fn register_peer(&self, config: &PeerConfig) -> Result<Peer, RegisterError> {
        let peer_key = config.public_key;
        let (rx, status) = self
            .router
            .register_peer(peer_key)
            .ok_or(RegisterError::AlreadyRegistered)?;
        let (data_tx, data_rx) = mpsc::channel(PEER_INBOUND_QUEUE);
        let (session_tx, session_rx) = watch::channel(false);
        spawn(
            PeerActor {
                our_key: self.our_key.clone(),
                peer_key,
                label: peer_label(&peer_key),
                endpoint: None,
                router: Arc::downgrade(&self.router),
                socket: self.socket.clone(),
                cookie_generator: Generator::new(peer_key),
                preshared_key: config.preshared_key,
                persistent_keepalive: config.persistent_keepalive,
                status: status.clone(),
                pending_handshake: None,
                current: None,
                next: None,
                previous: None,
                session_tx,
                staged: VecDeque::new(),
                data_tx,
            }
            .run(rx),
        );
        Ok(Peer {
            public_key: peer_key,
            router: Arc::downgrade(&self.router),
            status,
            session_rx,
            data_rx,
        })
    }

    /// Registers a peer and returns its handle, initiating a handshake if the
    /// config carries an endpoint. Errors if the peer is already registered.
    pub async fn add_peer(&self, config: PeerConfig) -> Result<Peer, RegisterError> {
        let peer = self.register_peer(&config)?;
        if let Some(endpoint) = config.endpoint {
            let _ = self.router.connect(&config.public_key, endpoint).await;
        }
        Ok(peer)
    }

    /// Registers a peer with no endpoint; it can only respond to inbound
    /// handshakes until [`Peer::connect`] gives it one.
    pub fn allow_peer(&self, peer_key: PublicKey) -> Result<Peer, RegisterError> {
        self.register_peer(&PeerConfig::new(peer_key))
    }

    /// Registers a peer with an endpoint and initiates a handshake.
    pub async fn connect_peer(
        &self,
        peer_key: PublicKey,
        endpoint: SocketAddr,
    ) -> Result<Peer, RegisterError> {
        self.add_peer(PeerConfig::new(peer_key).endpoint(endpoint))
            .await
    }

    /// The local UDP address the tunnel is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Status snapshots for every registered peer.
    pub fn peers(&self) -> Vec<PeerStatus> {
        self.router.peer_statuses()
    }

    /// Status snapshot for one peer, or `None` if it isn't registered.
    pub fn peer(&self, peer: &PublicKey) -> Option<PeerStatus> {
        self.router.peer_status(peer)
    }

    /// Binds the UDP socket and starts the tunnel's receive loop.
    pub async fn new(addr: SocketAddr, our_key: PrivateKey) -> io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        let router = Arc::new(RoutingTable::new());
        let under_load = Arc::new(AtomicBool::new(false));
        let read_task = spawn(Self::read_loop(
            our_key.clone(),
            socket.clone(),
            router.clone(),
            under_load.clone(),
        ));
        Ok(Self {
            our_key,
            socket,
            router,
            #[cfg(test)]
            under_load,
            read_task,
        })
    }

    #[cfg(test)]
    fn force_under_load(&self) {
        self.under_load.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use spacetun_protocol::handshake::RESP_MSG_LENGTH;

    use base64::{Engine, prelude::BASE64_STANDARD};

    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn loopback() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    // The responder is forced under load, so the initiator's first handshake is
    // answered with a cookie challenge; it must decrypt the cookie, retransmit
    // with a valid mac2, and complete — exercising both cookie directions.
    #[tokio::test(flavor = "multi_thread")]
    async fn cookie_under_load() {
        let sk_a = PrivateKey::random();
        let pk_a = sk_a.public_key();
        let sk_b = PrivateKey::random();
        let pk_b = sk_b.public_key();

        let tunnel_a = Tunnel::new(loopback(), sk_a).await.unwrap();
        let tunnel_b = Tunnel::new(loopback(), sk_b).await.unwrap();
        let addr_b = tunnel_b.local_addr().unwrap();
        tunnel_b.force_under_load();

        let mut peer_a = tunnel_b.allow_peer(pk_a).unwrap();
        let peer_b = tunnel_a.connect_peer(pk_b, addr_b).await.unwrap();

        tokio::time::timeout(Duration::from_secs(5), peer_b.ready())
            .await
            .expect("handshake did not complete through the cookie challenge")
            .unwrap();

        let payload = b"through the cookie".to_vec();
        peer_b.send(payload.clone()).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), peer_a.recv())
            .await
            .expect("payload not delivered")
            .unwrap();
        assert_eq!(got, payload);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn tunnel_e2e() {
        let sk_a = PrivateKey::random();
        let pk_a = sk_a.public_key();
        let sk_b = PrivateKey::random();
        let pk_b = sk_b.public_key();

        let tunnel_a = Tunnel::new(loopback(), sk_a).await.unwrap();
        let tunnel_b = Tunnel::new(loopback(), sk_b).await.unwrap();
        let addr_b = tunnel_b.local_addr().unwrap();

        // b is the responder; a initiates the handshake.
        let mut peer_a = tunnel_b.allow_peer(pk_a).unwrap();
        let mut peer_b = tunnel_a.connect_peer(pk_b, addr_b).await.unwrap();

        peer_b.ready().await.unwrap();
        peer_a.ready().await.unwrap();

        // the initiator confirms the session with a keepalive
        let keepalive_len = Transport::packet_len(0) as u64;
        let stat = peer_b.status();
        assert_eq!(stat.tx_bytes, INIT_MSG_LENGTH as u64 + keepalive_len);
        assert_eq!(stat.rx_bytes, RESP_MSG_LENGTH as u64);
        let a_rx = stat.rx_bytes;
        let a_tx = stat.tx_bytes;

        let stat = peer_a.status();
        assert_eq!(stat.tx_bytes, RESP_MSG_LENGTH as u64);
        assert_eq!(stat.rx_bytes, INIT_MSG_LENGTH as u64 + keepalive_len);
        let b_rx = stat.rx_bytes;
        let b_tx = stat.tx_bytes;

        let payload_a = b"hello from a".to_vec();
        let payload_a_len = Transport::packet_len(payload_a.len()) as u64;
        peer_b.send(payload_a.clone()).await.unwrap();
        let data = peer_a.recv().await;
        assert_eq!(data.unwrap(), payload_a);

        let stat = tunnel_b.peer(&pk_a).unwrap();
        let b_rx = b_rx + payload_a_len;
        assert_eq!(stat.tx_bytes, b_tx);
        assert_eq!(stat.rx_bytes, b_rx);

        let stat = tunnel_a.peer(&pk_b).unwrap();
        let a_tx = a_tx + payload_a_len;
        assert_eq!(stat.tx_bytes, a_tx);
        assert_eq!(stat.rx_bytes, a_rx);

        let payload_b = b"hello from b".to_vec();
        let payload_b_len = Transport::packet_len(payload_a.len()) as u64;
        peer_a.send(payload_b.clone()).await.unwrap();
        let data = peer_b.recv().await;
        assert_eq!(data.unwrap(), payload_b);

        let stat = tunnel_a.peer(&pk_b).unwrap();
        assert_eq!(stat.tx_bytes, a_tx);
        assert_eq!(stat.rx_bytes, a_rx + payload_b_len);

        let stat = tunnel_b.peer(&pk_a).unwrap();
        assert_eq!(stat.tx_bytes, b_tx + payload_b_len);
        assert_eq!(stat.rx_bytes, b_rx);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn staged_send() {
        let sk_a = PrivateKey::random();
        let pk_a = sk_a.public_key();
        let sk_b = PrivateKey::random();
        let pk_b = sk_b.public_key();

        let tunnel_a = Tunnel::new(loopback(), sk_a).await.unwrap();
        let tunnel_b = Tunnel::new(loopback(), sk_b).await.unwrap();
        let addr_b = tunnel_b.local_addr().unwrap();

        let mut peer_a = tunnel_b.allow_peer(pk_a).unwrap();
        let peer_b = tunnel_a.connect_peer(pk_b, addr_b).await.unwrap();

        // no readiness wait: the payload stages until the handshake completes
        let payload = b"staged before handshake".to_vec();
        peer_b.send(payload.clone()).await.unwrap();

        let data = tokio::time::timeout(Duration::from_secs(5), peer_a.recv())
            .await
            .expect("staged payload not delivered")
            .unwrap();
        assert_eq!(data, payload);
    }

    // a send to a peer with no known endpoint stays staged (no handshake
    // possible) until the peer connects to us.
    #[tokio::test(flavor = "multi_thread")]
    async fn send_before_endpoint_known() {
        let sk_a = PrivateKey::random();
        let pk_a = sk_a.public_key();
        let sk_b = PrivateKey::random();
        let pk_b = sk_b.public_key();

        let tunnel_a = Tunnel::new(loopback(), sk_a).await.unwrap();
        let tunnel_b = Tunnel::new(loopback(), sk_b).await.unwrap();
        let addr_b = tunnel_b.local_addr().unwrap();

        let peer_a = tunnel_b.allow_peer(pk_a).unwrap();
        let payload = b"staged before endpoint".to_vec();
        peer_a.send(payload.clone()).await.unwrap();
        assert!(peer_a.status().last_send.is_none());

        let mut peer_b = tunnel_a.connect_peer(pk_b, addr_b).await.unwrap();

        let data = tokio::time::timeout(Duration::from_secs(5), peer_b.recv())
            .await
            .expect("staged payload not delivered")
            .unwrap();
        assert_eq!(data, payload);
    }

    // the peer's inbound queue only closes once its actor has shut down,
    // which requires the tunnel drop to release the routing table
    #[tokio::test(flavor = "multi_thread")]
    async fn drop_terminates_actors() {
        let sk_a = PrivateKey::random();
        let sk_b = PrivateKey::random();
        let pk_b = sk_b.public_key();

        let tunnel_a = Tunnel::new(loopback(), sk_a).await.unwrap();
        let mut peer_b = tunnel_a.allow_peer(pk_b).unwrap();
        drop(tunnel_a);

        let closed = tokio::time::timeout(Duration::from_secs(2), peer_b.recv())
            .await
            .expect("peer actor leaked after tunnel drop");
        assert!(closed.is_none());
        assert_eq!(
            peer_b.send(b"closed".to_vec()).await,
            Err(SendError::Closed)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_registration() {
        let sk_a = PrivateKey::random();
        let sk_b = PrivateKey::random();
        let pk_b = sk_b.public_key();

        let tunnel_a = Tunnel::new(loopback(), sk_a).await.unwrap();
        let peer_b = tunnel_a.allow_peer(pk_b).unwrap();
        assert_eq!(
            tunnel_a.allow_peer(pk_b).err(),
            Some(RegisterError::AlreadyRegistered)
        );

        // dropping the handle unregisters the peer and frees the key
        drop(peer_b);
        assert!(tunnel_a.peer(&pk_b).is_none());
        let _peer_b = tunnel_a.allow_peer(pk_b).unwrap();
        assert!(tunnel_a.peer(&pk_b).is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn preshared_key() {
        let sk_a = PrivateKey::random();
        let pk_a = sk_a.public_key();
        let sk_b = PrivateKey::random();
        let pk_b = sk_b.public_key();
        let psk = [7u8; 32];

        let tunnel_a = Tunnel::new(loopback(), sk_a).await.unwrap();
        let tunnel_b = Tunnel::new(loopback(), sk_b).await.unwrap();
        let addr_b = tunnel_b.local_addr().unwrap();

        let mut peer_a = tunnel_b
            .add_peer(PeerConfig::new(pk_a).preshared_key(psk))
            .await
            .unwrap();
        let peer_b = tunnel_a
            .add_peer(PeerConfig::new(pk_b).endpoint(addr_b).preshared_key(psk))
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(5), peer_b.ready())
            .await
            .expect("handshake did not complete")
            .unwrap();

        let payload = b"psk".to_vec();
        peer_b.send(payload.clone()).await.unwrap();
        let data = tokio::time::timeout(Duration::from_secs(5), peer_a.recv())
            .await
            .expect("payload not delivered")
            .unwrap();
        assert_eq!(data, payload);
    }

    // a mismatched preshared key must not complete a handshake, and the
    // invalid response must not trigger an immediate re-initiation storm
    #[tokio::test(flavor = "multi_thread")]
    async fn preshared_key_mismatch() {
        let sk_a = PrivateKey::random();
        let pk_a = sk_a.public_key();
        let sk_b = PrivateKey::random();
        let pk_b = sk_b.public_key();

        let tunnel_a = Tunnel::new(loopback(), sk_a).await.unwrap();
        let tunnel_b = Tunnel::new(loopback(), sk_b).await.unwrap();
        let addr_b = tunnel_b.local_addr().unwrap();

        let _peer_a = tunnel_b
            .add_peer(PeerConfig::new(pk_a).preshared_key([1u8; 32]))
            .await
            .unwrap();
        let peer_b = tunnel_a
            .add_peer(
                PeerConfig::new(pk_b)
                    .endpoint(addr_b)
                    .preshared_key([2u8; 32]),
            )
            .await
            .unwrap();

        assert!(
            tokio::time::timeout(Duration::from_secs(1), peer_b.ready())
                .await
                .is_err()
        );
        // one init sent; the invalid response was dropped without re-initiating
        assert_eq!(peer_b.status().tx_bytes, INIT_MSG_LENGTH as u64);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn persistent_keepalive() {
        let sk_a = PrivateKey::random();
        let pk_a = sk_a.public_key();
        let sk_b = PrivateKey::random();
        let pk_b = sk_b.public_key();

        let tunnel_a = Tunnel::new(loopback(), sk_a).await.unwrap();
        let tunnel_b = Tunnel::new(loopback(), sk_b).await.unwrap();
        let addr_b = tunnel_b.local_addr().unwrap();

        let peer_a = tunnel_b.allow_peer(pk_a).unwrap();
        let peer_b = tunnel_a
            .add_peer(
                PeerConfig::new(pk_b)
                    .endpoint(addr_b)
                    .persistent_keepalive(Duration::from_millis(100)),
            )
            .await
            .unwrap();
        peer_b.ready().await.unwrap();

        let sent = peer_b.status().tx_bytes;
        tokio::time::sleep(Duration::from_millis(550)).await;

        let keepalive_len = Transport::packet_len(0) as u64;
        let sent = peer_b.status().tx_bytes - sent;
        assert!(
            sent >= 3 * keepalive_len,
            "expected at least 3 keepalives, sent {sent} bytes"
        );
        assert!(peer_a.status().rx_bytes >= INIT_MSG_LENGTH as u64 + 3 * keepalive_len);
    }

    #[test]
    fn key_base64_roundtrip() {
        let secret = PrivateKey::random();
        let public = secret.public_key();
        let encoded = public.to_string();
        assert_eq!(encoded.len(), 44);
        assert_eq!(encoded.parse::<PublicKey>().unwrap(), public);
        assert_eq!(
            secret
                .to_base64()
                .parse::<PrivateKey>()
                .unwrap()
                .public_key(),
            public
        );
        assert_eq!(format!("{secret:?}"), "PrivateKey(…)");

        assert_eq!(
            "!".repeat(44).parse::<PublicKey>().err(),
            Some(KeyParseError::InvalidEncoding)
        );
        assert_eq!(
            BASE64_STANDARD.encode([0u8; 16]).parse::<PublicKey>().err(),
            Some(KeyParseError::InvalidLength)
        );
    }
}
