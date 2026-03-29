//! HTTP CONNECT proxy handler.
//!
//! Parses the CONNECT request line, validates the target (domain,
//! port, no private IPs), checks lease state, and either establishes
//! a time-bounded bidirectional TCP tunnel or returns 403.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use super::SharedLeaseState;

/// Maximum bytes for the CONNECT request line.
const MAX_REQUEST_LINE: usize = 8192;

/// Maximum number of headers to consume after the request line.
const MAX_HEADERS: usize = 64;

/// Maximum tunnel duration (even with an active lease, connections
/// are forcibly closed after this).
const MAX_TUNNEL_DURATION: Duration = Duration::from_secs(3600); // 1 hour

/// Ports allowed for CONNECT tunneling.
const ALLOWED_PORTS: &[u16] = &[443, 8443];

/// Handle one explicit proxy connection (HTTP CONNECT).
pub async fn handle_connect(
    stream: TcpStream,
    peer_addr: SocketAddr,
    state: &SharedLeaseState,
) -> std::io::Result<()> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);

    // Read the request line with a size limit (Finding 1).
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;
    if request_line.len() > MAX_REQUEST_LINE {
        writer.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await?;
        return Ok(());
    }

    let (host, port) = match parse_connect_target(&request_line) {
        Some(t) => t,
        None => {
            writer.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await?;
            tracing::debug!(peer = %peer_addr, "bad CONNECT request line");
            return Ok(());
        }
    };

    // Consume remaining headers with a count limit (Finding 2).
    for _ in 0..MAX_HEADERS {
        let mut header = String::new();
        reader.read_line(&mut header).await?;
        if header.len() > MAX_REQUEST_LINE || header.trim().is_empty() {
            break;
        }
    }

    // Validate port (Finding 3a).
    if !ALLOWED_PORTS.contains(&port) {
        writer.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
        tracing::warn!(peer = %peer_addr, host = %host, port, "CONNECT blocked: port not allowed");
        return Ok(());
    }

    // Validate hostname characters (Finding 3d).
    if !is_valid_hostname(&host) {
        writer.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await?;
        tracing::warn!(peer = %peer_addr, host = %host, "CONNECT blocked: invalid hostname");
        return Ok(());
    }

    // Normalize domain to lowercase (Finding 6).
    let domain = host.to_ascii_lowercase();

    // Check lease state.
    let (allowed, tunnel_timeout) = {
        let guard = state.read().await;
        let ok = guard.is_allowed(&domain);
        // Get lease expiry for tunnel timeout (Finding 7).
        let timeout = guard
            .leases
            .get(&domain)
            .map(|info| {
                let remaining = info.expires_at - chrono::Utc::now();
                Duration::from_secs(remaining.num_seconds().max(0) as u64)
            })
            .unwrap_or(Duration::ZERO)
            .min(MAX_TUNNEL_DURATION);
        (ok, timeout)
    };

    if !allowed {
        writer.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
        tracing::warn!(peer = %peer_addr, domain = %domain, "CONNECT blocked: no active lease");
        return Ok(());
    }

    // Resolve and validate the target IP (Finding 3c — block private IPs).
    let target_str = format!("{domain}:{port}");
    let resolved_addr = match resolve_and_validate(&target_str) {
        Ok(addr) => addr,
        Err(reason) => {
            // Generic 502 — don't leak details (Finding 4).
            writer.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
            tracing::warn!(peer = %peer_addr, target = %target_str, reason = %reason, "CONNECT blocked");
            return Ok(());
        }
    };

    // Connect to the validated IP (not the raw hostname).
    let upstream = match TcpStream::connect(resolved_addr).await {
        Ok(s) => s,
        Err(e) => {
            // Generic 502 — don't leak error details (Finding 4).
            writer.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
            tracing::warn!(peer = %peer_addr, target = %target_str, error = %e, "upstream failed");
            return Ok(());
        }
    };

    writer.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
    tracing::info!(peer = %peer_addr, domain = %domain, "CONNECT tunnel established");

    // Reassemble the client stream.
    let client_stream = reader.into_inner().unsplit(writer);

    // Bidirectional tunnel with timeout (Finding 7 + Finding 12).
    let tunnel = async {
        let (mut client_read, mut client_write) = tokio::io::split(client_stream);
        let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);

        tokio::select! {
            r = tokio::io::copy(&mut client_read, &mut upstream_write) => {
                if let Err(e) = r { tracing::debug!(domain = %domain, error = %e, "client→upstream ended"); }
            }
            r = tokio::io::copy(&mut upstream_read, &mut client_write) => {
                if let Err(e) = r { tracing::debug!(domain = %domain, error = %e, "upstream→client ended"); }
            }
        }
    };

    if tokio::time::timeout(tunnel_timeout, tunnel).await.is_err() {
        tracing::info!(domain = %domain, "tunnel timed out (lease expired)");
    }

    Ok(())
}

/// Parse "CONNECT host:port HTTP/1.x" → (host, port).
/// Returns None for malformed lines.
fn parse_connect_target(line: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 || !parts[0].eq_ignore_ascii_case("CONNECT") {
        return None;
    }

    let target = parts[1];
    let (host, port_str) = target.rsplit_once(':')?;
    let port: u16 = port_str.parse().ok()?;

    if host.is_empty() {
        return None;
    }

    Some((host.to_string(), port))
}

/// Validate that a hostname contains only DNS-safe characters.
fn is_valid_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        && !host.starts_with('-')
        && !host.starts_with('.')
}

/// Resolve a hostname and validate the resulting IP is not private/internal.
fn resolve_and_validate(target: &str) -> Result<SocketAddr, &'static str> {
    let addrs: Vec<SocketAddr> = target
        .to_socket_addrs()
        .map_err(|_| "DNS resolution failed")?
        .collect();

    let addr = addrs.first().ok_or("DNS returned no addresses")?;

    if is_private_ip(addr.ip()) {
        return Err("resolved to private/internal IP");
    }

    Ok(*addr)
}

/// Check if an IP is private, link-local, loopback, or otherwise internal.
fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()          // 127.0.0.0/8
                || v4.is_private()    // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                || v4.is_link_local() // 169.254.0.0/16 (AWS metadata!)
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64 // 100.64.0.0/10 (CGNAT)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified()
            // IPv6 should be disabled in the VM, but belt-and-suspenders.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease_state::{LeaseInfo, LeaseState};
    use chrono::{Duration as CDuration, Utc};
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;
    use tokio::sync::RwLock;

    #[test]
    fn parse_valid_connect() {
        let (host, port) = parse_connect_target("CONNECT github.com:443 HTTP/1.1\r\n").expect("should parse");
        assert_eq!(host, "github.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_non_standard_port() {
        let (host, port) = parse_connect_target("CONNECT example.com:8443 HTTP/1.1\r\n").expect("should parse");
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);
    }

    #[test]
    fn parse_missing_port() {
        assert!(parse_connect_target("CONNECT github.com HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn parse_not_connect() {
        assert!(parse_connect_target("GET / HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn parse_empty() {
        assert!(parse_connect_target("").is_none());
    }

    #[test]
    fn hostname_validation() {
        assert!(is_valid_hostname("github.com"));
        assert!(is_valid_hostname("api.github.com"));
        assert!(is_valid_hostname("a-b.c-d.example.com"));
        assert!(!is_valid_hostname(""));
        assert!(!is_valid_hostname("-bad.com"));
        assert!(!is_valid_hostname(".bad.com"));
        assert!(!is_valid_hostname("evil.com/../../etc/passwd"));
        assert!(!is_valid_hostname("has spaces.com"));
    }

    #[test]
    fn private_ip_detection() {
        assert!(is_private_ip("127.0.0.1".parse().expect("parse")));
        assert!(is_private_ip("10.0.0.1".parse().expect("parse")));
        assert!(is_private_ip("172.16.0.1".parse().expect("parse")));
        assert!(is_private_ip("192.168.1.1".parse().expect("parse")));
        assert!(is_private_ip("169.254.169.254".parse().expect("parse"))); // AWS metadata
        assert!(!is_private_ip("8.8.8.8".parse().expect("parse")));
        assert!(!is_private_ip("140.82.114.4".parse().expect("parse"))); // github.com
    }

    fn make_state(entries: &[(&str, bool)]) -> SharedLeaseState {
        let mut state = LeaseState::new();
        for (domain, active) in entries {
            let expires = if *active {
                Utc::now() + CDuration::hours(1)
            } else {
                Utc::now() - CDuration::hours(1)
            };
            state.leases.insert(
                domain.to_string(),
                LeaseInfo {
                    lease_id: "test".to_string(),
                    expires_at: expires,
                },
            );
        }
        Arc::new(RwLock::new(state))
    }

    #[tokio::test]
    async fn connect_private_ip_gets_502() {
        // Verify that CONNECT to a localhost address is blocked by IP validation.
        let proxy = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy_addr = proxy.local_addr().expect("addr");
        // Lease for "localhost" exists but IP validation should still block.
        let state = make_state(&[("localhost", true)]);

        let proxy_task = tokio::spawn(async move {
            let (stream, peer) = proxy.accept().await.expect("accept");
            handle_connect(stream, peer, &state).await.expect("handle");
        });

        let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
        client
            .write_all(b"CONNECT localhost:443 HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .expect("send");

        let mut response = String::new();
        BufReader::new(&mut client).read_line(&mut response).await.expect("read");
        assert!(
            response.contains("502"),
            "private IP should get 502, got: {response}"
        );

        proxy_task.await.expect("proxy task");
    }

    #[tokio::test]
    async fn connect_denied_domain_gets_403() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy_addr = proxy.local_addr().expect("addr");
        let state = make_state(&[]);

        let proxy_task = tokio::spawn(async move {
            let (stream, peer) = proxy.accept().await.expect("accept");
            handle_connect(stream, peer, &state).await.expect("handle");
        });

        let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
        client
            .write_all(b"CONNECT evil.com:443 HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .expect("send");

        let mut response = String::new();
        BufReader::new(&mut client).read_line(&mut response).await.expect("read");
        assert!(response.contains("403"), "expected 403, got: {response}");

        proxy_task.await.expect("proxy task");
    }

    #[tokio::test]
    async fn connect_disallowed_port_gets_403() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy_addr = proxy.local_addr().expect("addr");
        let state = make_state(&[("github.com", true)]);

        let proxy_task = tokio::spawn(async move {
            let (stream, peer) = proxy.accept().await.expect("accept");
            handle_connect(stream, peer, &state).await.expect("handle");
        });

        let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
        // Port 22 (SSH) should be blocked even with a valid domain lease.
        client
            .write_all(b"CONNECT github.com:22 HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .expect("send");

        let mut response = String::new();
        BufReader::new(&mut client).read_line(&mut response).await.expect("read");
        assert!(response.contains("403"), "SSH port should be blocked: {response}");

        proxy_task.await.expect("proxy task");
    }

    #[tokio::test]
    async fn connect_invalid_hostname_gets_400() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy_addr = proxy.local_addr().expect("addr");
        let state = make_state(&[]);

        let proxy_task = tokio::spawn(async move {
            let (stream, peer) = proxy.accept().await.expect("accept");
            handle_connect(stream, peer, &state).await.expect("handle");
        });

        let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
        client
            .write_all(b"CONNECT ../../etc/passwd:443 HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .expect("send");

        let mut response = String::new();
        BufReader::new(&mut client).read_line(&mut response).await.expect("read");
        assert!(response.contains("400"), "path traversal should get 400: {response}");

        proxy_task.await.expect("proxy task");
    }
}
