use std::{
    collections::{HashMap, VecDeque},
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, RwLock, Weak},
    task::{Context, Poll},
    time::{Duration, SystemTime},
};

use base64::{Engine, prelude::BASE64_STANDARD};
use bytes::BytesMut;
use log::debug;
use quinn_udp::{BATCH_SIZE, RecvMeta};
use spacetun_protocol::{
    MessageHeader, Tai64N,
    cookies::{Generator, Verifier},
    handshake::{self, Handshake, INIT_MSG_LENGTH, InitReceived, InitSent},
    transport::Transport,
};
pub use spacetun_protocol::{PublicKey, StaticSecret};
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

mod pool;
mod socket;
use pool::{BufferPool, RefGuard};
use socket::UdpSocket;

const MAX_MESSAGE_SIZE: usize = 65535;
const BUFFER_POOL_SIZE: usize = 256;
const MAX_STAGED_PACKETS: usize = 128;
const PEER_INBOUND_QUEUE: usize = 1024;

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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyParseError {
    #[error("invalid base64")]
    InvalidEncoding,

    #[error("invalid key length")]
    InvalidLength,
}

/// Decodes a key from the standard WireGuard base64 encoding. Convert with
/// `PublicKey::from` or `StaticSecret::from`.
pub fn key_from_base64(s: &str) -> Result<[u8; 32], KeyParseError> {
    let bytes = BASE64_STANDARD
        .decode(s)
        .map_err(|_| KeyParseError::InvalidEncoding)?;
    <[u8; 32]>::try_from(bytes).map_err(|_| KeyParseError::InvalidLength)
}

/// Encodes a key in the standard WireGuard base64 encoding.
pub fn key_to_base64(key: &[u8; 32]) -> String {
    BASE64_STANDARD.encode(key)
}

#[derive(Debug, Clone)]
pub struct PeerConfig {
    public_key: PublicKey,
    endpoint: Option<SocketAddr>,
    preshared_key: Option<[u8; 32]>,
    persistent_keepalive: Option<Duration>,
}

impl PeerConfig {
    pub fn new(public_key: PublicKey) -> Self {
        Self {
            public_key,
            endpoint: None,
            preshared_key: None,
            persistent_keepalive: None,
        }
    }

    pub fn endpoint(mut self, endpoint: SocketAddr) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    pub fn preshared_key(mut self, preshared_key: [u8; 32]) -> Self {
        self.preshared_key = Some(preshared_key);
        self
    }

    pub fn persistent_keepalive(mut self, interval: Duration) -> Self {
        self.persistent_keepalive = Some(interval);
        self
    }
}

enum PeerAction {
    Connect(SocketAddr),
    SendData(Vec<u8>),
    RecvData(RefGuard, SocketAddr),
    RecvHandshakeInit(Handshake<InitReceived>, SocketAddr),
    RecvHandshakeResp(RefGuard, SocketAddr),
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
    first_sent: Instant,
    last_sent: Instant,
}

struct Session {
    transport: Arc<Transport>,
    initiator: bool,
    established: Instant,
    last_send: Instant,

    // passive keepalive owed to the peer, armed on receiving data
    keepalive_at: Option<Instant>,
    // first data send with no authenticated receive since
    unanswered_send: Option<Instant>,
}

struct PeerActor {
    our_key: StaticSecret,
    peer_key: PublicKey,
    endpoint: Option<SocketAddr>,

    // weak so dropping the Tunnel terminates the peer actors
    router: Weak<RoutingTable>,

    // TODO: implement cookies
    cookie_generator: Generator,
    #[allow(unused)]
    cookie_verifier: Verifier,

    preshared_key: Option<[u8; 32]>,
    persistent_keepalive: Option<Duration>,

    pending_handshake: Option<PendingHandshake>,
    session: Option<Session>,
    session_tx: watch::Sender<bool>,
    staged: VecDeque<Vec<u8>>,

    socket: Arc<UdpSocket>,
    pool: Arc<BufferPool>,

    status: Arc<RwLock<PeerStatus>>,

    data_tx: Sender<Vec<u8>>,
}

impl PeerActor {
    fn establish_session(&mut self, transport: Transport, initiator: bool, endpoint: SocketAddr) {
        let now = Instant::now();
        let old = self.session.replace(Session {
            transport: Arc::new(transport),
            initiator,
            established: now,
            last_send: now,
            keepalive_at: None,
            unanswered_send: None,
        });
        if let (Some(old), Some(router)) = (old, self.router.upgrade()) {
            router.retire_index(old.transport.our_index());
        }
        self.endpoint = Some(endpoint);
        self.session_tx.send_replace(true);
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
            PeerAction::RecvData(mut data, endpoint) => {
                let now = Instant::now();
                let Some(session) = &self.session else {
                    return;
                };
                if now.duration_since(session.established) >= REJECT_AFTER_TIME {
                    return;
                }
                let transport = session.transport.clone();
                let rx_bytes = data.len() as u64;
                match transport.receive(&mut data) {
                    Ok(payload) => {
                        let payload = (!payload.is_empty()).then(|| payload.to_vec());
                        let session = self.session.as_mut().unwrap();
                        session.unanswered_send = None;
                        if payload.is_some() && session.keepalive_at.is_none() {
                            session.keepalive_at = Some(now + KEEPALIVE_TIMEOUT);
                        }
                        self.endpoint = Some(endpoint);
                        self.update_status(|status| {
                            status.endpoint = Some(endpoint);
                            status.rx_bytes += rx_bytes;
                            status.last_recv = Some(SystemTime::now());
                        });
                        if let Some(payload) = payload {
                            // drop on a full queue rather than await: a slow or absent
                            // reader must not stall the actor's timers and handshakes
                            if let Err(mpsc::error::TrySendError::Full(_)) =
                                self.data_tx.try_send(payload)
                            {
                                debug!("dropping inbound packet: receive queue full");
                            }
                        }
                    }
                    Err(e) => debug!("failed to decrypt inbound packet: {:?}", e),
                }
            }
            PeerAction::RecvHandshakeInit(handshake, endpoint) => {
                let mut msg = BytesMut::zeroed(handshake::RESP_MSG_LENGTH);
                let ephemeral_secret = StaticSecret::random();
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
                    debug!("failed to send handshake response: {:?}", e);
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
                self.establish_session(new_transport, false, endpoint);
                self.flush_staged().await;
            }
            PeerAction::RecvHandshakeResp(mut resp, endpoint) => {
                let rx_bytes = resp.len() as u64;
                let Some(pending) = self.pending_handshake.as_ref() else {
                    debug!("dropping unexpected handshake response");
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
                        self.establish_session(established.finish(), true, endpoint);
                        self.flush_staged().await;
                    }
                    // an invalid response is dropped; the pending handshake keeps
                    // its retransmit schedule
                    Err(e) => debug!("dropping invalid handshake response: {:?}", e),
                }
            }
        }
    }

    async fn start_handshake(&mut self, now: Instant, first_sent: Instant) {
        let (Some(endpoint), Some(router)) = (self.endpoint, self.router.upgrade()) else {
            return;
        };
        let our_index = rand::random();
        let ephemeral_secret = StaticSecret::random();
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
        if let Some(old) = self.pending_handshake.replace(PendingHandshake {
            state,
            our_index,
            first_sent,
            last_sent: now,
        }) {
            router.retire_index(old.our_index);
        }
        router.bind_index(&self.peer_key, our_index);
        if let Err(e) = self.socket.send(endpoint, &msg).await {
            debug!("failed to send handshake init: {:?}", e);
            return;
        }
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
        let now = Instant::now();
        let usable = self.endpoint.and_then(|endpoint| {
            self.session.as_ref().and_then(|session| {
                (now.duration_since(session.established) < REJECT_AFTER_TIME).then(|| {
                    (
                        endpoint,
                        session.transport.clone(),
                        session.initiator,
                        session.established,
                    )
                })
            })
        });
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
            let mut batch = self.pool.clone().pop();
            batch.resize((end - start) * segment_size, 0);
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
                Err(e) => debug!("failed to send outbound packets: {:?}", e),
            }
            start = end;
        }
        payloads.clear();
        if sent && let Some(session) = self.session.as_mut() {
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
        let (Some(endpoint), Some(session)) = (self.endpoint, self.session.as_ref()) else {
            return;
        };
        let transport = session.transport.clone();
        let mut msg = self.pool.clone().pop();
        msg.resize(Transport::packet_len(0), 0);
        transport.send(&[], &mut msg);
        if let Err(e) = self.socket.send(endpoint, &msg).await {
            debug!("failed to send keepalive: {:?}", e);
            return;
        }
        if let Some(session) = self.session.as_mut() {
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
            .session
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
        [retransmit, keepalive, silence, persistent]
            .into_iter()
            .flatten()
            .min()
    }

    async fn tick(&mut self) {
        let now = Instant::now();
        if let Some(pending) = &self.pending_handshake
            && now >= pending.last_sent + REKEY_TIMEOUT
        {
            if now.duration_since(pending.first_sent) >= REKEY_ATTEMPT_TIME {
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
            self.ensure_handshake(now).await;
        }
    }

    pub async fn run(mut self, mut rx: Receiver<PeerAction>) {
        let mut actions = Vec::with_capacity(BATCH_SIZE);
        let mut payloads = Vec::with_capacity(BATCH_SIZE);
        loop {
            let deadline = self.next_deadline();
            select! {
                n = rx.recv_many(&mut actions, BATCH_SIZE) => {
                    if n == 0 {
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

    async fn send_data(&self, public_key: &PublicKey, packet: Vec<u8>) -> Result<(), SendError> {
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
        packet: RefGuard,
    ) -> bool {
        if let Some(sender) = self.peer_index_sender(peer_index) {
            let _ = sender
                .send(PeerAction::RecvHandshakeResp(packet, endpoint))
                .await;
            return true;
        }
        false
    }

    async fn recv_data(&self, endpoint: SocketAddr, peer_index: u32, packet: RefGuard) -> bool {
        if let Some(sender) = self.peer_index_sender(peer_index) {
            let _ = sender.send(PeerAction::RecvData(packet, endpoint)).await;
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
    data_rx: mpsc::Receiver<Vec<u8>>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        if let Some(router) = self.router.upgrade() {
            router.remove_peer(&self.public_key);
        }
    }
}

impl Peer {
    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    pub fn status(&self) -> PeerStatus {
        self.status.read().unwrap().clone()
    }

    /// Receives the next decrypted payload from this peer. Returns `None`
    /// once the peer is removed or the tunnel is dropped.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.data_rx.recv().await
    }

    pub async fn send(&self, payload: Vec<u8>) -> Result<(), SendError> {
        let router = self.router.upgrade().ok_or(SendError::Closed)?;
        router.send_data(&self.public_key, payload).await
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
        let mut session_rx = self.session_rx.clone();
        loop {
            if *session_rx.borrow_and_update() {
                return Ok(());
            }
            session_rx.changed().await.map_err(|_| SendError::Closed)?;
        }
    }
}

impl futures_core::Stream for Peer {
    type Item = Vec<u8>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().data_rx.poll_recv(cx)
    }
}

pub struct Tunnel {
    our_key: StaticSecret,
    socket: Arc<UdpSocket>,
    router: Arc<RoutingTable>,
    pool: Arc<BufferPool>,
    read_task: JoinHandle<()>,
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.read_task.abort();
    }
}

impl Tunnel {
    async fn read_loop(
        our_private: StaticSecret,
        socket: Arc<UdpSocket>,
        router: Arc<RoutingTable>,
        pool: Arc<BufferPool>,
    ) {
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
                            let mut packet = pool.clone().pop();
                            packet.extend_from_slice(segment);
                            let _ = router
                                .recv_handshake_resp(meta.addr, receiver, packet)
                                .await;
                        }
                        MessageHeader::Data { receiver } => {
                            let mut packet = pool.clone().pop();
                            packet.extend_from_slice(segment);
                            let _ = router.recv_data(meta.addr, receiver, packet).await;
                        }
                        MessageHeader::CookieReply { receiver: _ } => {
                            unimplemented!()
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
                endpoint: None,
                router: Arc::downgrade(&self.router),
                socket: self.socket.clone(),
                pool: self.pool.clone(),
                cookie_generator: Generator::new(peer_key),
                cookie_verifier: Verifier::new(peer_key),
                preshared_key: config.preshared_key,
                persistent_keepalive: config.persistent_keepalive,
                status: status.clone(),
                pending_handshake: None,
                session: None,
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

    pub async fn add_peer(&self, config: PeerConfig) -> Result<Peer, RegisterError> {
        let peer = self.register_peer(&config)?;
        if let Some(endpoint) = config.endpoint {
            let _ = self.router.connect(&config.public_key, endpoint).await;
        }
        Ok(peer)
    }

    pub fn allow_peer(&self, peer_key: PublicKey) -> Result<Peer, RegisterError> {
        self.register_peer(&PeerConfig::new(peer_key))
    }

    pub async fn connect_peer(
        &self,
        peer_key: PublicKey,
        endpoint: SocketAddr,
    ) -> Result<Peer, RegisterError> {
        self.add_peer(PeerConfig::new(peer_key).endpoint(endpoint))
            .await
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn peers(&self) -> Vec<PeerStatus> {
        self.router.peer_statuses()
    }

    pub fn peer(&self, peer: &PublicKey) -> Option<PeerStatus> {
        self.router.peer_status(peer)
    }

    pub async fn new(addr: SocketAddr, our_key: StaticSecret) -> io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        let router = Arc::new(RoutingTable::new());
        let pool = Arc::new(BufferPool::new(BUFFER_POOL_SIZE));
        let read_task = spawn(Self::read_loop(
            our_key.clone(),
            socket.clone(),
            router.clone(),
            pool.clone(),
        ));
        Ok(Self {
            our_key,
            socket,
            router,
            pool,
            read_task,
        })
    }
}

#[cfg(test)]
mod tests {
    use spacetun_protocol::handshake::RESP_MSG_LENGTH;

    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn loopback() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn tunnel_e2e() {
        let sk_a = StaticSecret::random();
        let pk_a = PublicKey::from(&sk_a);
        let sk_b = StaticSecret::random();
        let pk_b = PublicKey::from(&sk_b);

        let tunnel_a = Tunnel::new(loopback(), sk_a).await.unwrap();
        let tunnel_b = Tunnel::new(loopback(), sk_b).await.unwrap();
        let addr_b = tunnel_b.local_addr().unwrap();

        // b is the responder; a initiates the handshake.
        let mut peer_a = tunnel_b.allow_peer(pk_a).unwrap();
        let mut peer_b = tunnel_a.connect_peer(pk_b, addr_b).await.unwrap();

        peer_b.ready().await.unwrap();
        peer_a.ready().await.unwrap();

        let stat = peer_b.status();
        assert_eq!(stat.tx_bytes, INIT_MSG_LENGTH as u64);
        assert_eq!(stat.rx_bytes, RESP_MSG_LENGTH as u64);
        let a_rx = stat.rx_bytes;
        let a_tx = stat.tx_bytes;

        let stat = peer_a.status();
        assert_eq!(stat.tx_bytes, RESP_MSG_LENGTH as u64);
        assert_eq!(stat.rx_bytes, INIT_MSG_LENGTH as u64);
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
        let sk_a = StaticSecret::random();
        let pk_a = PublicKey::from(&sk_a);
        let sk_b = StaticSecret::random();
        let pk_b = PublicKey::from(&sk_b);

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
        let sk_a = StaticSecret::random();
        let pk_a = PublicKey::from(&sk_a);
        let sk_b = StaticSecret::random();
        let pk_b = PublicKey::from(&sk_b);

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
        let sk_a = StaticSecret::random();
        let sk_b = StaticSecret::random();
        let pk_b = PublicKey::from(&sk_b);

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
        let sk_a = StaticSecret::random();
        let sk_b = StaticSecret::random();
        let pk_b = PublicKey::from(&sk_b);

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
        let sk_a = StaticSecret::random();
        let pk_a = PublicKey::from(&sk_a);
        let sk_b = StaticSecret::random();
        let pk_b = PublicKey::from(&sk_b);
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
        let sk_a = StaticSecret::random();
        let pk_a = PublicKey::from(&sk_a);
        let sk_b = StaticSecret::random();
        let pk_b = PublicKey::from(&sk_b);

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
        let sk_a = StaticSecret::random();
        let pk_a = PublicKey::from(&sk_a);
        let sk_b = StaticSecret::random();
        let pk_b = PublicKey::from(&sk_b);

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
        let secret = StaticSecret::random();
        let encoded = key_to_base64(PublicKey::from(&secret).as_bytes());
        assert_eq!(encoded.len(), 44);
        let decoded = key_from_base64(&encoded).unwrap();
        assert_eq!(&decoded, PublicKey::from(&secret).as_bytes());

        assert_eq!(
            key_from_base64("not base64!").err(),
            Some(KeyParseError::InvalidEncoding)
        );
        assert_eq!(
            key_from_base64(&BASE64_STANDARD.encode([0u8; 16])).err(),
            Some(KeyParseError::InvalidLength)
        );
    }
}
