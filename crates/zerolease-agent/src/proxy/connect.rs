//! HTTP CONNECT proxy handler.
//!
//! Parses the CONNECT request line, extracts the target host,
//! checks lease state, and either establishes a bidirectional
//! TCP tunnel or returns 403.

use std::net::SocketAddr;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use super::SharedLeaseState;

/// Handle one explicit proxy connection (HTTP CONNECT).
///
/// Reads the CONNECT request line, validates the target domain
/// against the lease state, and either tunnels or rejects.
pub async fn handle_connect(
    stream: TcpStream,
    peer_addr: SocketAddr,
    state: &SharedLeaseState,
) -> std::io::Result<()> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);

    // Read the request line: "CONNECT host:port HTTP/1.1\r\n"
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;

    let target = match parse_connect_target(&request_line) {
        Some(t) => t,
        None => {
            let response = "HTTP/1.1 400 Bad Request\r\n\r\n";
            writer.write_all(response.as_bytes()).await?;
            tracing::debug!(peer = %peer_addr, line = %request_line.trim(), "bad CONNECT request");
            return Ok(());
        }
    };

    // Consume remaining headers (we don't need them).
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).await?;
        if header.trim().is_empty() {
            break;
        }
    }

    // Extract the domain (strip port if present).
    let domain = target
        .split(':')
        .next()
        .unwrap_or(&target);

    // Check lease state.
    let allowed = {
        let guard = state.read().await;
        guard.is_allowed(domain)
    };

    if !allowed {
        let response = "HTTP/1.1 403 Forbidden\r\n\r\nLease expired or domain not allowed\r\n";
        writer.write_all(response.as_bytes()).await?;
        tracing::warn!(
            peer = %peer_addr,
            domain = domain,
            "CONNECT blocked: no active lease"
        );
        return Ok(());
    }

    // Connect to the target.
    let upstream = match TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            let response = format!("HTTP/1.1 502 Bad Gateway\r\n\r\n{e}\r\n");
            writer.write_all(response.as_bytes()).await?;
            tracing::warn!(
                peer = %peer_addr,
                target = %target,
                error = %e,
                "CONNECT upstream connection failed"
            );
            return Ok(());
        }
    };

    // Send 200 to indicate tunnel established.
    writer.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

    tracing::info!(
        peer = %peer_addr,
        domain = domain,
        "CONNECT tunnel established"
    );

    // Reassemble the client stream from the split halves.
    let client_stream = reader.into_inner().unsplit(writer);

    // Bidirectional tunnel.
    let (mut client_read, mut client_write) = tokio::io::split(client_stream);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);

    let client_to_upstream = tokio::io::copy(&mut client_read, &mut upstream_write);
    let upstream_to_client = tokio::io::copy(&mut upstream_read, &mut client_write);

    // Run both directions concurrently; when either side closes, we're done.
    tokio::select! {
        result = client_to_upstream => {
            if let Err(e) = result {
                tracing::debug!(domain = domain, error = %e, "client→upstream copy ended");
            }
        }
        result = upstream_to_client => {
            if let Err(e) = result {
                tracing::debug!(domain = domain, error = %e, "upstream→client copy ended");
            }
        }
    }

    Ok(())
}

/// Parse "CONNECT host:port HTTP/1.x" and return "host:port".
fn parse_connect_target(line: &str) -> Option<String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 2 && parts[0].eq_ignore_ascii_case("CONNECT") {
        Some(parts[1].to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease_state::{LeaseInfo, LeaseState};
    use chrono::{Duration, Utc};
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;
    use tokio::sync::RwLock;

    #[test]
    fn parse_valid_connect() {
        assert_eq!(
            parse_connect_target("CONNECT github.com:443 HTTP/1.1\r\n"),
            Some("github.com:443".to_string())
        );
    }

    #[test]
    fn parse_lowercase_connect() {
        assert_eq!(
            parse_connect_target("connect example.com:8443 HTTP/1.1\r\n"),
            Some("example.com:8443".to_string())
        );
    }

    #[test]
    fn parse_not_connect() {
        assert_eq!(parse_connect_target("GET / HTTP/1.1\r\n"), None);
    }

    #[test]
    fn parse_empty() {
        assert_eq!(parse_connect_target(""), None);
    }

    /// Build a SharedLeaseState with the given domain→expiry mappings.
    fn make_state(entries: &[(&str, bool)]) -> SharedLeaseState {
        let mut state = LeaseState::new();
        for (domain, active) in entries {
            let expires = if *active {
                Utc::now() + Duration::hours(1)
            } else {
                Utc::now() - Duration::hours(1)
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
    async fn connect_allowed_domain_gets_200() {
        // Start a mock upstream server.
        let upstream = TcpListener::bind("127.0.0.1:0").await.expect("bind upstream");
        let upstream_addr = upstream.local_addr().expect("upstream addr");

        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.expect("accept upstream");
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).await.expect("read from tunnel");
            stream.write_all(&buf[..n]).await.expect("echo back");
        });

        // Start proxy with the upstream's address as the allowed domain.
        let proxy = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
        let proxy_addr = proxy.local_addr().expect("proxy addr");

        let state = make_state(&[("127.0.0.1", true)]);

        let proxy_task = tokio::spawn(async move {
            let (stream, peer) = proxy.accept().await.expect("accept proxy");
            handle_connect(stream, peer, &state).await.expect("handle_connect");
        });

        // Client sends CONNECT to the proxy.
        let mut client = TcpStream::connect(proxy_addr).await.expect("connect to proxy");
        let connect_req = format!("CONNECT {upstream_addr} HTTP/1.1\r\nHost: {upstream_addr}\r\n\r\n");
        client.write_all(connect_req.as_bytes()).await.expect("send CONNECT");

        // Read the response status line.
        let mut reader = BufReader::new(&mut client);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).await.expect("read status");
        assert!(
            status_line.contains("200"),
            "expected 200 Connection Established, got: {status_line}"
        );

        // Drain the rest of the headers.
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await.expect("read header");
            if line.trim().is_empty() {
                break;
            }
        }

        // Send data through the tunnel and get echo back.
        let inner = reader.into_inner();
        inner.write_all(b"hello tunnel").await.expect("write through tunnel");

        let mut response = vec![0u8; 12];
        inner.read_exact(&mut response).await.expect("read echo");
        assert_eq!(&response, b"hello tunnel", "tunnel should echo data");

        proxy_task.await.expect("proxy task");
        upstream_task.await.expect("upstream task");
    }

    #[tokio::test]
    async fn connect_denied_domain_gets_403() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy_addr = proxy.local_addr().expect("addr");

        // No leases — everything denied.
        let state = make_state(&[]);

        let proxy_task = tokio::spawn(async move {
            let (stream, peer) = proxy.accept().await.expect("accept");
            handle_connect(stream, peer, &state).await.expect("handle");
        });

        let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
        client
            .write_all(b"CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com\r\n\r\n")
            .await
            .expect("send CONNECT");

        let mut response = String::new();
        let mut reader = BufReader::new(&mut client);
        reader.read_line(&mut response).await.expect("read");
        assert!(
            response.contains("403"),
            "expected 403 Forbidden, got: {response}"
        );

        proxy_task.await.expect("proxy task");
    }

    #[tokio::test]
    async fn connect_expired_lease_gets_403() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy_addr = proxy.local_addr().expect("addr");

        // Expired lease.
        let state = make_state(&[("expired.com", false)]);

        let proxy_task = tokio::spawn(async move {
            let (stream, peer) = proxy.accept().await.expect("accept");
            handle_connect(stream, peer, &state).await.expect("handle");
        });

        let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
        client
            .write_all(b"CONNECT expired.com:443 HTTP/1.1\r\nHost: expired.com\r\n\r\n")
            .await
            .expect("send");

        let mut response = String::new();
        let mut reader = BufReader::new(&mut client);
        reader.read_line(&mut response).await.expect("read");
        assert!(
            response.contains("403"),
            "expired lease should get 403, got: {response}"
        );

        proxy_task.await.expect("proxy task");
    }
}
