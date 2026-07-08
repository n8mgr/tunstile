use std::{
    io::{self, IoSliceMut},
    net::SocketAddr,
};

use quinn_udp::{RecvMeta, Transmit, UdpSocketState};
use tokio::{
    io::Interest,
    net::{ToSocketAddrs, UdpSocket as TokioUdpSocket},
};

pub(crate) struct UdpSocket {
    socket: TokioUdpSocket,
    socket_state: UdpSocketState,
}

impl UdpSocket {
    pub async fn bind(addr: impl ToSocketAddrs) -> io::Result<Self> {
        let socket = TokioUdpSocket::bind(addr).await?;
        let socket_state = UdpSocketState::new((&socket).into())?;

        #[cfg(target_vendor = "apple")]
        unsafe {
            socket_state.set_apple_fast_path();
        }
        Ok(Self {
            socket,
            socket_state,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub async fn recv(
        &self,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> io::Result<usize> {
        loop {
            self.socket.readable().await?;
            match self.socket.try_io(Interest::READABLE, || {
                self.socket_state.recv((&self.socket).into(), bufs, meta)
            }) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }

    async fn transmit(
        &self,
        endpoint: SocketAddr,
        payload: &[u8],
        segment_size: Option<usize>,
    ) -> io::Result<()> {
        loop {
            self.socket.writable().await?;
            match self.socket.try_io(Interest::WRITABLE, || {
                self.socket_state.send(
                    (&self.socket).into(),
                    &Transmit {
                        destination: endpoint,
                        ecn: None,
                        contents: payload,
                        segment_size,
                        src_ip: None,
                    },
                )
            }) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }

    pub fn max_gso_segments(&self) -> usize {
        self.socket_state.max_gso_segments()
    }

    pub async fn send(&self, endpoint: SocketAddr, payload: &[u8]) -> io::Result<()> {
        self.transmit(endpoint, payload, None).await
    }

    /// Sends multiple equal-length datagrams in a single syscall where the
    /// platform supports it. `payload` holds the datagrams back-to-back at
    /// `segment_size` offsets.
    pub async fn send_segments(
        &self,
        endpoint: SocketAddr,
        payload: &[u8],
        segment_size: usize,
    ) -> io::Result<()> {
        self.transmit(endpoint, payload, Some(segment_size)).await
    }
}
