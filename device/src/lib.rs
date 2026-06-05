use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, RwLock},
};

use bytes::BytesMut;
use chrono::{DateTime, Utc};
use log::debug;
use spacetun_protocol::{
    MessageHeader,
    cookies::{Generator, Verifier},
    handshake::{INIT_MSG_LENGTH, InitReceived, InitSent},
};
pub use spacetun_protocol::{
    PublicKey, StaticSecret, Tai64N, cookies,
    handshake::{self, Handshake},
    transport::Transport,
};
use tokio::{
    net::UdpSocket,
    spawn,
    sync::mpsc::{self, Receiver, Sender},
    task::JoinHandle,
};

const MAX_MESSAGE_SIZE: usize = 65535;

enum PeerAction {
    SendHandshake,
    SendData(Vec<u8>),
    RecvData(Vec<u8>, SocketAddr),
    RecvHandshakeInit(Handshake<InitReceived>, SocketAddr),
    RecvHandshakeResp(Vec<u8>, SocketAddr),
}

#[derive(Clone, Debug)]
pub struct PeerStatus {
    public_key: PublicKey,
    endpoint: Option<SocketAddr>,

    tx_bytes: u64,
    rx_bytes: u64,

    last_send: Option<DateTime<Utc>>,
    last_recv: Option<DateTime<Utc>>,
    last_successful_handshake: Option<DateTime<Utc>>,
}

struct PeerActor {
    our_key: StaticSecret,
    peer_key: PublicKey,
    endpoint: SocketAddr,

    router: Arc<RoutingTable>,
    cookie_generator: Generator,
    cookie_verifier: Verifier,

    handshake: Option<Handshake<InitSent>>,
    transport: Option<Transport>,

    socket: Arc<UdpSocket>,

    status: Arc<RwLock<PeerStatus>>,

    // temporary: surfaces decrypted inbound payloads to the test harness
    data_tx: Sender<Vec<u8>>,
}

impl PeerActor {
    fn rotate_transport(&mut self, new_transport: Transport) {
        if let Some(old_transport) = self.transport.replace(new_transport) {
            self.router.retire_index(old_transport.our_index());
        }
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
            PeerAction::SendHandshake => {
                let our_index = rand::random();
                let ephemeral_secret = StaticSecret::random();
                let timestamp = Tai64N::now();
                let mut msg = vec![0u8; handshake::INIT_MSG_LENGTH];
                let handshake = Handshake::initiate(
                    self.our_key.clone(),
                    self.peer_key,
                    our_index,
                    ephemeral_secret,
                    timestamp,
                    &self.cookie_generator,
                    &mut msg,
                );
                self.handshake = Some(handshake);
                if let Err(e) = self.socket.send_to(&msg, self.endpoint).await {
                    debug!("Failed to send handshake response: {:?}", e);
                    return;
                }
                self.update_status(|status| {
                    status.tx_bytes += msg.len() as u64;
                    status.last_send = Some(Utc::now());
                });
                self.router.bind_index(&self.peer_key, our_index);
            }
            PeerAction::SendData(payload) => {
                if let Some(transport) = &mut self.transport {
                    let mut msg = BytesMut::zeroed(Transport::packet_len(payload.len()));
                    transport.send(&payload, &mut msg);
                    let _ = self
                        .socket
                        .send_to(&msg, self.endpoint)
                        .await
                        .inspect(|n| {
                            self.update_status(|status| {
                                status.tx_bytes += *n as u64;
                                status.last_send = Some(Utc::now());
                            });
                        })
                        .inspect_err(|e| {
                            debug!("Failed to send outbound packet: {:?}", e);
                        });
                }
            }
            PeerAction::RecvData(mut data, endpoint) => {
                let rx_bytes = data.len() as u64;
                if let Some(transport) = &mut self.transport {
                    let data = transport.receive(&mut data).unwrap(); // TODO: handle error
                    self.endpoint = endpoint;
                    let _ = self.data_tx.send(data.to_vec()).await;
                    self.update_status(|status| {
                        status.endpoint = Some(endpoint);
                        status.rx_bytes += rx_bytes;
                        status.last_recv = Some(Utc::now());
                    });
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
                        None,
                        timestamp,
                        &self.cookie_generator,
                        &mut msg,
                    )
                    .finish();
                if let Err(e) = self.socket.send_to(&msg, endpoint).await {
                    debug!("Failed to send handshake response: {:?}", e);
                    return;
                }
                self.router.bind_index(&self.peer_key, our_index);
                self.rotate_transport(new_transport);
                self.endpoint = endpoint;
                self.update_status(|status| {
                    status.endpoint = Some(endpoint);
                    status.rx_bytes += INIT_MSG_LENGTH as u64;
                    status.last_recv = Some(Utc::now());
                    status.tx_bytes += msg.len() as u64;
                    status.last_send = Some(Utc::now());
                    status.last_successful_handshake = Some(Utc::now());
                });
            }
            PeerAction::RecvHandshakeResp(mut resp, endpoint) => {
                let rx_bytes = resp.len() as u64;
                let handshake = self.handshake.take().unwrap(); // TODO: handle error
                let new_transport = handshake
                    .response_received(None, &mut resp)
                    .unwrap() // TODO: handle error
                    .finish();
                self.rotate_transport(new_transport);
                self.endpoint = endpoint;
                self.update_status(|status| {
                    status.endpoint = Some(endpoint);
                    status.rx_bytes += rx_bytes;
                    status.last_recv = Some(Utc::now());
                    status.last_successful_handshake = Some(Utc::now());
                });
            }
        }
    }

    pub async fn run(mut self, mut rx: Receiver<PeerAction>) {
        while let Some(msg) = rx.recv().await {
            self.handle_message(msg).await
        }
    }
}

struct RoutingTable {
    peer_indices: RwLock<HashMap<u32, mpsc::Sender<PeerAction>>>,
    peer_keys: RwLock<HashMap<PublicKey, mpsc::Sender<PeerAction>>>,
}

impl RoutingTable {
    fn new() -> Self {
        Self {
            peer_indices: RwLock::new(HashMap::new()),
            peer_keys: RwLock::new(HashMap::new()),
        }
    }

    fn bind_index(&self, peer_key: &PublicKey, index: u32) -> bool {
        let sender = self.peer_keys.read().unwrap().get(peer_key).cloned();
        if sender.is_none() {
            return false;
        }
        self.peer_indices
            .write()
            .unwrap()
            .insert(index, sender.unwrap());
        true
    }

    fn retire_index(&self, index: u32) {
        self.peer_indices.write().unwrap().remove(&index);
    }

    fn register_peer(&self, peer_key: PublicKey) -> Option<mpsc::Receiver<PeerAction>> {
        let mut peer_keys = self.peer_keys.write().unwrap();
        if peer_keys.contains_key(&peer_key) {
            return None;
        }
        let (tx, rx) = mpsc::channel(1024);
        peer_keys.insert(peer_key, tx);
        Some(rx)
    }

    fn peer_key_sender(&self, public_key: &PublicKey) -> Option<Sender<PeerAction>> {
        self.peer_keys.read().unwrap().get(public_key).cloned()
    }

    fn peer_index_sender(&self, index: u32) -> Option<Sender<PeerAction>> {
        self.peer_indices.read().unwrap().get(&index).cloned()
    }

    async fn send_handshake(&self, public_key: &PublicKey) -> bool {
        if let Some(sender) = self.peer_key_sender(public_key) {
            let _ = sender.send(PeerAction::SendHandshake).await;
            return true;
        }
        false
    }

    async fn send_data(&self, public_key: &PublicKey, packet: Vec<u8>) -> bool {
        if let Some(sender) = self.peer_key_sender(public_key) {
            let _ = sender.send(PeerAction::SendData(packet)).await;
            return true;
        }
        false
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
            let _ = sender.send(PeerAction::RecvData(packet, endpoint)).await;
            return true;
        }
        false
    }
}

pub struct Tunnel {
    our_key: StaticSecret,
    socket: Arc<UdpSocket>,
    router: Arc<RoutingTable>,
    peer_status: RwLock<HashMap<PublicKey, Arc<RwLock<PeerStatus>>>>,
    read_task: JoinHandle<()>,

    // temporary: cloned into each peer actor so the test can observe decrypted data
    data_tx: Sender<Vec<u8>>,
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
    ) {
        loop {
            let mut message = vec![0u8; MAX_MESSAGE_SIZE];
            let (n, src) = socket.recv_from(&mut message).await.unwrap(); // TODO: handle error
            message.truncate(n);
            let header = MessageHeader::try_from(message.as_ref()).unwrap(); // TODO: handle error
            match header {
                MessageHeader::HandshakeInit => {
                    let handshake = Handshake::receive(our_private.clone(), &mut message).unwrap(); // TODO: handle error
                    let _ = router.recv_handshake_init(src, handshake).await;
                }
                MessageHeader::HandshakeResponse { receiver } => {
                    let _ = router.recv_handshake_resp(src, receiver, message).await;
                }
                MessageHeader::Data { receiver } => {
                    let _ = router.recv_data(src, receiver, message).await;
                }
                MessageHeader::CookieReply { receiver: _ } => {
                    unimplemented!()
                }
            };
        }
    }

    fn register_peer(&self, peer_key: PublicKey, endpoint: SocketAddr) {
        if let Some(rx) = self.router.register_peer(peer_key) {
            let status = Arc::new(RwLock::new(PeerStatus {
                public_key: peer_key,
                rx_bytes: 0,
                tx_bytes: 0,
                endpoint: None,
                last_send: None,
                last_recv: None,
                last_successful_handshake: None,
            }));
            spawn(
                PeerActor {
                    our_key: self.our_key.clone(),
                    peer_key,
                    endpoint,
                    router: self.router.clone(),
                    socket: self.socket.clone(),
                    cookie_generator: Generator::new(peer_key),
                    cookie_verifier: Verifier::new(peer_key),
                    status: status.clone(),
                    handshake: None,
                    transport: None,
                    data_tx: self.data_tx.clone(),
                }
                .run(rx),
            );
            self.peer_status.write().unwrap().insert(peer_key, status);
        }
    }

    pub fn allow_peer(&self, peer_key: PublicKey) {
        self.register_peer(
            peer_key,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0),
        );
    }

    pub async fn connect_peer(&self, peer_key: PublicKey, endpoint: SocketAddr) {
        self.register_peer(peer_key, endpoint);
        let _ = self.router.send_handshake(&peer_key).await;
    }

    pub async fn send(&self, peer_key: PublicKey, payload: Vec<u8>) -> bool {
        self.router.send_data(&peer_key, payload).await
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn peers(&self) -> Vec<PeerStatus> {
        self.peer_status
            .read()
            .unwrap()
            .values()
            .map(|ps| ps.read().unwrap().clone())
            .collect()
    }

    pub fn peer(&self, peer: &PublicKey) -> Option<PeerStatus> {
        self.peer_status
            .read()
            .unwrap()
            .get(peer)
            .map(|ps| ps.read().unwrap().clone())
    }

    // returns a receiver of decrypted inbound payloads (temporary, for tests)
    pub async fn new(
        addr: SocketAddr,
        our_key: StaticSecret,
    ) -> io::Result<(Self, mpsc::Receiver<Vec<u8>>)> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        let router = Arc::new(RoutingTable::new());
        let (data_tx, data_rx) = mpsc::channel(64);
        let read_task = spawn(Self::read_loop(
            our_key.clone(),
            socket.clone(),
            router.clone(),
        ));
        Ok((
            Self {
                our_key,
                socket,
                router,
                read_task,
                data_tx,

                peer_status: RwLock::new(HashMap::new()),
            },
            data_rx,
        ))
    }
}

#[cfg(test)]
mod tests {
    use spacetun_protocol::handshake::RESP_MSG_LENGTH;

    use super::*;
    use std::{thread::sleep, time::Duration};

    fn loopback() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    // resends to absorb the handshake-completion race, then asserts the payload
    // arrives decrypted on `rx`.
    fn assert_peer_ready(from: &Tunnel, peer: &PublicKey) {
        for _ in 0..40 {
            if let Some(ps) = from.peer(peer)
                && ps.last_successful_handshake.is_some()
            {
                return;
            }
            sleep(Duration::from_millis(50));
        }
        panic!("peer not ready before timeout");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn tunnel_e2e() {
        let sk_a = StaticSecret::random();
        let pk_a = PublicKey::from(&sk_a);
        let sk_b = StaticSecret::random();
        let pk_b = PublicKey::from(&sk_b);

        let (tunnel_a, mut rx_a) = Tunnel::new(loopback(), sk_a).await.unwrap();
        let (tunnel_b, mut rx_b) = Tunnel::new(loopback(), sk_b).await.unwrap();
        let addr_b = tunnel_b.local_addr().unwrap();

        // b is the responder; a initiates the handshake.
        tunnel_b.allow_peer(pk_a);
        tunnel_a.connect_peer(pk_b, addr_b).await;

        assert_peer_ready(&tunnel_a, &pk_b);
        assert_peer_ready(&tunnel_b, &pk_a);

        let stat = tunnel_a.peer(&pk_b).unwrap();
        assert_eq!(stat.tx_bytes, INIT_MSG_LENGTH as u64);
        assert_eq!(stat.rx_bytes, RESP_MSG_LENGTH as u64);
        let a_rx = stat.rx_bytes;
        let a_tx = stat.tx_bytes;

        let stat = tunnel_b.peer(&pk_a).unwrap();
        assert_eq!(stat.tx_bytes, RESP_MSG_LENGTH as u64);
        assert_eq!(stat.rx_bytes, INIT_MSG_LENGTH as u64);
        let b_rx = stat.rx_bytes;
        let b_tx = stat.tx_bytes;

        let payload_a = b"hello from a".to_vec();
        let payload_a_len = Transport::packet_len(payload_a.len()) as u64;
        tunnel_a.send(pk_b, payload_a.clone()).await;
        let data = rx_b.recv().await;
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
        tunnel_b.send(pk_a, payload_b.clone()).await;
        let data = rx_a.recv().await;
        assert_eq!(data.unwrap(), payload_b);

        let stat = tunnel_a.peer(&pk_b).unwrap();
        assert_eq!(stat.tx_bytes, a_tx);
        assert_eq!(stat.rx_bytes, a_rx + payload_b_len);

        let stat = tunnel_b.peer(&pk_a).unwrap();
        assert_eq!(stat.tx_bytes, b_tx + payload_b_len);
        assert_eq!(stat.rx_bytes, b_rx);
    }
}
