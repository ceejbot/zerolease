//! TCP transport for vault client↔server communication.
//!
//! Designed for QEMU VMs reaching a host-side vault via user-mode
//! networking (`-netdev user,hostfwd=...`). The listener binds to
//! localhost only — not exposed to the network.
//!
//! TCP peers authenticate via a token included in the [`ClientHello`]
//! handshake message. The token is hashed (SHA-256) and stored in
//! [`PeerIdentity::Tcp`] for audit logging.

use std::net::SocketAddr;

use tokio::net::{TcpListener as TokioTcpListener, TcpStream};

use crate::error::{Error, Result};
use crate::transport::{PeerIdentity, VaultConnector, VaultListener};

/// A TCP listener bound to `127.0.0.1` on the given port.
///
/// Returns [`PeerIdentity::Tcp`] with the peer's socket address and
/// a zeroed token hash. The token hash is populated later by the
/// server after parsing the `ClientHello`.
pub struct TcpListener {
    inner: TokioTcpListener,
}

impl TcpListener {
    /// Bind to `127.0.0.1:{port}`.
    pub async fn bind(port: u16) -> Result<Self> {
        let addr: SocketAddr = ([127, 0, 0, 1], port).into();
        let inner = TokioTcpListener::bind(addr)
            .await
            .map_err(|e| Error::Transport(format!("failed to bind TCP listener on {addr}: {e}")))?;
        Ok(Self { inner })
    }

    /// The local address this listener is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.inner
            .local_addr()
            .map_err(|e| Error::Transport(format!("failed to get local address: {e}")))
    }
}

#[async_trait::async_trait]
impl VaultListener for TcpListener {
    type Stream = TcpStream;

    async fn accept(&self) -> Result<(Self::Stream, PeerIdentity)> {
        let (stream, addr) = self
            .inner
            .accept()
            .await
            .map_err(|e| Error::Transport(format!("TCP accept failed: {e}")))?;

        // Return with zeroed token hash — will be enriched after
        // ClientHello is parsed in handle_connection.
        let peer = PeerIdentity::Tcp {
            addr,
            token_hash: [0u8; 32],
        };

        Ok((stream, peer))
    }
}

/// A TCP connector that connects to a vault server at a given address.
///
/// The token is stored here so `VaultClient::connect_with_token` can
/// retrieve it for the `ClientHello`.
pub struct TcpConnector {
    addr: SocketAddr,
    token: String,
}

impl TcpConnector {
    /// Create a connector targeting the given address with an auth token.
    pub fn new(addr: SocketAddr, token: impl Into<String>) -> Self {
        Self {
            addr,
            token: token.into(),
        }
    }

    /// The authentication token for this connection.
    pub fn token(&self) -> &str {
        &self.token
    }
}

#[async_trait::async_trait]
impl VaultConnector for TcpConnector {
    type Stream = TcpStream;

    async fn connect(&self) -> Result<Self::Stream> {
        TcpStream::connect(self.addr)
            .await
            .map_err(|e| Error::Transport(format!("TCP connect to {} failed: {e}", self.addr)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::frame::{read_frame, write_frame};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn listener_binds_and_accepts() {
        let listener = TcpListener::bind(0).await.expect("should bind to ephemeral port");
        let addr = listener.local_addr().expect("should have local addr");

        let client_task = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.expect("should connect");
            stream.write_all(b"hello").await.expect("should write");
            stream.shutdown().await.expect("should shutdown");
        });

        let (mut stream, peer) = listener.accept().await.expect("should accept");
        assert!(matches!(peer, PeerIdentity::Tcp { .. }), "peer should be Tcp variant");

        let mut buf = vec![0u8; 5];
        stream.read_exact(&mut buf).await.expect("should read");
        assert_eq!(&buf, b"hello");

        client_task.await.expect("client task should complete");
    }

    #[tokio::test]
    async fn connector_connects_and_sends_frames() {
        let listener = TcpListener::bind(0).await.expect("should bind");
        let addr = listener.local_addr().expect("should have addr");

        let server_task = tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.expect("should accept");
            let (mut reader, mut writer) = tokio::io::split(stream);
            let frame = read_frame(&mut reader).await.expect("should read frame");
            assert_eq!(frame, b"test payload");
            write_frame(&mut writer, b"response").await.expect("should write frame");
        });

        let connector = TcpConnector::new(addr, "test-token");
        assert_eq!(connector.token(), "test-token");

        let stream = connector.connect().await.expect("should connect");
        let (mut reader, mut writer) = tokio::io::split(stream);
        write_frame(&mut writer, b"test payload").await.expect("should write frame");
        let response = read_frame(&mut reader).await.expect("should read response");
        assert_eq!(response, b"response");

        server_task.await.expect("server task should complete");
    }

    #[tokio::test]
    async fn peer_identity_display() {
        let peer = PeerIdentity::Tcp {
            addr: ([127, 0, 0, 1], 1234).into(),
            token_hash: [0xab; 32],
        };
        let display = peer.to_string();
        assert!(display.contains("127.0.0.1:1234"), "should show addr: {display}");
        assert!(display.contains("abababab"), "should show token hash prefix: {display}");
    }
}
