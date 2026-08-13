//! The per-peer driver: owns the sans-IO state machine, its liveness
//! schedule, and the staged-send queue.

use std::{
    collections::VecDeque,
    future::pending,
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
    time::{Instant, sleep},
};
use tunstile_protocol::{
    PrivateKey, PublicKey, ReusableSecret, Tai64N,
    handshake::{Handshake, INIT_MSG_LENGTH, InitReceived, RESP_MSG_LENGTH},
    peer::{HandshakeValues, Peer as PeerState, REKEY_ATTEMPT_TIME},
    time::Instant as Timestamp,
    transport::Transport,
};

use crate::{Packet, PeerConfig, PeerStatus, router::Control, socket::UdpSocket};

mod timers;

use timers::{HandshakeTimers, SessionTimers};

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

struct PeerActor {
    label: String,
    our_key: Arc<PrivateKey>,
    machine: PeerState,
    clock: Clock,

    // index-routing updates for the read loop
    control: mpsc::UnboundedSender<Control>,

    persistent_keepalive: Option<Duration>,
    handshake: Option<HandshakeTimers>,
    session: Option<SessionTimers>,

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
        self.handshake = Some(HandshakeTimers::new(first_sent, now));
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
        let mut encrypted_any = false;
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
        if sent && let Some(session) = self.session.as_mut() {
            session.data_sent(now);
            rekey |= session.rekey_after_send(now);
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
            session.keepalive_sent(now);
        }
        let sent = match self.socket.send(endpoint, &msg[..len]).await {
            Ok(()) => {
                debug!("[{}] sent keepalive", self.label);
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

    fn next_deadline(&self) -> Option<Timestamp> {
        let handshake = self.handshake.map(|handshake| handshake.next_deadline());
        let session = self
            .session
            .as_ref()
            .map(|session| session.next_deadline(self.persistent_keepalive));
        match (handshake, session) {
            (Some(handshake), Some(session)) => Some(handshake.min(session)),
            (handshake, session) => handshake.or(session),
        }
    }

    async fn fire_due_timers(&mut self, now: Timestamp) {
        if self.session.as_ref().is_some_and(|s| s.expired(now)) {
            // the machine already refuses expired sessions; drop our timers
            debug!("[{}] session expired", self.label);
            self.session = None;
        }
        if let Some(handshake) = self.handshake
            && handshake.due(now)
        {
            if handshake.attempts_exhausted(now) {
                debug!(
                    "[{}] handshake abandoned after {:?}",
                    self.label, REKEY_ATTEMPT_TIME
                );
                self.handshake = None;
                self.staged.clear();
                let abandoned = self.machine.abandon_handshake();
                self.retire_index(abandoned);
            } else {
                self.send_handshake(handshake.first_sent()).await;
            }
        }
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let due = session.due(now, self.persistent_keepalive);
        if due.keepalive {
            self.send_keepalive().await;
        }
        if due.new_handshake {
            self.ensure_handshake().await;
        }
    }

    async fn run(mut self, mut rx: Receiver<PeerAction>) {
        debug!("[{}] peer added", self.label);
        let mut actions = Vec::with_capacity(BATCH_SIZE);
        let mut payloads = Vec::with_capacity(BATCH_SIZE);
        loop {
            let now = self.clock.now();
            self.fire_due_timers(now).await;
            let wait = self
                .next_deadline()
                .map(|deadline| deadline.duration_since(now));
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
                () = wait_until(wait) => {}
            }
        }
    }
}

async fn wait_until(deadline: Option<Duration>) {
    match deadline {
        Some(deadline) => sleep(deadline).await,
        None => pending().await,
    }
}

fn peer_label(key: &PublicKey) -> String {
    let b64 = key.to_string();
    format!("{}…{}", &b64[..4], &b64[39..43])
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
