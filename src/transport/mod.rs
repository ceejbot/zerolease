//! Transport abstraction for vault client↔server communication.
//!
//! The vault server needs to accept connections over different transports
//! depending on the deployment environment:
//!
//! - **Unix domain socket**: developer laptops, local development
//! - **TCP**: QEMU VMs reaching the host vault via user-mode networking
//! - **vsock**: Firecracker and QEMU VMs communicating with the host
//!
//! All transports provide a bidirectional byte stream. We abstract over
//! them so the vault protocol (request/response framing, serialization)
//! is transport-agnostic.

use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::Result;

/// SHA-256 hash of a token, used for audit logging without exposing
/// the raw token value.
pub type TokenHash = [u8; 32];

pub mod tcp;
pub mod uds;
#[cfg(feature = "vsock")]
pub mod vsock;

/// A bidirectional async byte stream. Both Unix sockets and vsock
/// connections implement AsyncRead + AsyncWrite, so we can treat
/// them uniformly.
pub trait VaultStream: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

// Blanket impl: anything that's AsyncRead + AsyncWrite + Send + Unpin is a
// VaultStream.
impl<T> VaultStream for T where T: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

/// Server-side transport listener. Accepts incoming connections from
/// agents and yields streams.
#[async_trait::async_trait]
pub trait VaultListener: Send + Sync + 'static {
    /// The concrete stream type this listener produces.
    type Stream: VaultStream;

    /// Accept the next incoming connection.
    async fn accept(&self) -> Result<(Self::Stream, PeerIdentity)>;
}

/// Identity of the connecting peer, derived from the transport layer.
///
/// - Unix sockets: UID/PID via SO_PEERCRED
/// - vsock: guest CID (maps to a specific VM)
/// - TCP: peer address + token hash (token presented in ClientHello)
///
/// This provides a transport-level identity that can be cross-referenced
/// with the agent's presented AgentId for defense-in-depth.
#[derive(Debug, Clone)]
pub enum PeerIdentity {
    /// Unix socket peer: UID and PID from SO_PEERCRED.
    Unix { uid: u32, pid: u32 },

    /// vsock peer: the guest's context ID.
    Vsock { cid: u32 },

    /// TCP peer: socket address and SHA-256 hash of the auth token.
    /// The raw token is never stored here — only its hash for audit.
    Tcp {
        addr: SocketAddr,
        token_hash: TokenHash,
    },

    /// Unknown or unauthenticated peer (e.g., during testing).
    Anonymous,
}

impl PeerIdentity {
    /// Update the token hash on a TCP peer identity after extracting
    /// the token from the ClientHello.
    pub fn set_token_hash(&mut self, hash: TokenHash) {
        if let PeerIdentity::Tcp { token_hash, .. } = self {
            *token_hash = hash;
        }
    }
}

impl std::fmt::Display for PeerIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerIdentity::Unix { uid, pid } => write!(f, "unix(uid={uid}, pid={pid})"),
            PeerIdentity::Vsock { cid } => write!(f, "vsock(cid={cid})"),
            PeerIdentity::Tcp { addr, token_hash } => {
                // Show first 8 bytes of token hash as hex for audit correlation.
                let short: String = token_hash[..8].iter().map(|b| format!("{b:02x}")).collect();
                write!(f, "tcp(addr={addr}, token={short})")
            }
            PeerIdentity::Anonymous => write!(f, "anonymous"),
        }
    }
}

/// Compute the SHA-256 hash of a token string for use in [`PeerIdentity::Tcp`].
pub fn hash_token(token: &str) -> TokenHash {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().into()
}

/// Client-side transport connector. Used by agents to connect to the vault.
#[async_trait::async_trait]
pub trait VaultConnector: Send + Sync + 'static {
    /// The concrete stream type this connector produces.
    type Stream: VaultStream;

    /// Connect to the vault server.
    async fn connect(&self) -> Result<Self::Stream>;
}
