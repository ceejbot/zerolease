//! Transparent proxy handler: extracts domain from TLS SNI.
//!
//! When iptables redirects port 443 traffic to this listener,
//! we see the raw TLS ClientHello. We peek at the first bytes
//! to extract the SNI hostname, check lease state, then either
//! tunnel to the original destination or drop the connection.
//!
//! **This is defense-in-depth.** The explicit proxy (CONNECT) is
//! the primary enforcement path. Deny when SNI is absent.

use std::net::SocketAddr;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use super::SharedLeaseState;

/// Maximum bytes to peek for the TLS ClientHello.
/// Modern TLS 1.3 with many extensions and key shares can exceed
/// 4 KiB. 16 KiB is the maximum TLS record size.
const MAX_CLIENT_HELLO: usize = 16384;

/// Handle one transparent proxy connection.
///
/// Peeks at the TLS ClientHello to extract SNI, checks lease state,
/// and tunnels if allowed.
pub async fn handle_transparent(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    state: &SharedLeaseState,
) -> std::io::Result<()> {
    // Peek at the incoming bytes without consuming them.
    let mut buf = vec![0u8; MAX_CLIENT_HELLO];
    let n = stream.peek(&mut buf).await?;

    let domain = match extract_sni(&buf[..n]) {
        Some(d) => d,
        None => {
            // No SNI = deny. Could be ECH, missing extension, or non-TLS.
            tracing::warn!(
                peer = %peer_addr,
                "transparent proxy: no SNI found, dropping connection"
            );
            stream.shutdown().await.ok();
            return Ok(());
        }
    };

    // Normalize to lowercase (Finding 6).
    let domain = domain.to_ascii_lowercase();

    // Check lease state.
    let allowed = {
        let guard = state.read().await;
        guard.is_allowed(&domain)
    };

    if !allowed {
        tracing::warn!(
            peer = %peer_addr,
            domain = %domain,
            "transparent proxy: no active lease, dropping"
        );
        stream.shutdown().await.ok();
        return Ok(());
    }

    // Connect to the original destination.
    // In transparent mode, the destination is the domain from SNI on port 443.
    let target = format!("{domain}:443");
    let upstream = match TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                peer = %peer_addr,
                target = %target,
                error = %e,
                "transparent proxy: upstream connection failed"
            );
            stream.shutdown().await.ok();
            return Ok(());
        }
    };

    tracing::info!(
        peer = %peer_addr,
        domain = %domain,
        "transparent tunnel established"
    );

    // Bidirectional tunnel. The peeked bytes are still in the stream's
    // buffer — they'll be read normally by the upstream when we copy.
    let (mut client_read, mut client_write) = tokio::io::split(stream);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);

    let c2u = tokio::io::copy(&mut client_read, &mut upstream_write);
    let u2c = tokio::io::copy(&mut upstream_read, &mut client_write);

    tokio::select! {
        r = c2u => { if let Err(e) = r { tracing::debug!(error = %e, "client→upstream ended"); } }
        r = u2c => { if let Err(e) = r { tracing::debug!(error = %e, "upstream→client ended"); } }
    }

    Ok(())
}

/// Extract the SNI hostname from a TLS ClientHello.
///
/// Parses just enough of the TLS record to find the server_name
/// extension. Returns `None` if the data is not a valid ClientHello
/// or the SNI extension is absent.
pub fn extract_sni(data: &[u8]) -> Option<String> {
    // TLS record header: type(1) + version(2) + length(2)
    if data.len() < 5 {
        return None;
    }

    // Content type 22 = Handshake
    if data[0] != 22 {
        return None;
    }

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    let handshake = data.get(5..5 + record_len)?;

    // Handshake header: type(1) + length(3)
    if handshake.is_empty() || handshake[0] != 1 {
        // type 1 = ClientHello
        return None;
    }

    let hello_len = u24_to_usize(handshake.get(1..4)?)?;
    let hello = handshake.get(4..4 + hello_len)?;

    // ClientHello: version(2) + random(32) = 34 bytes
    if hello.len() < 34 {
        return None;
    }
    let mut pos = 34;

    // Session ID: length(1) + data
    let session_id_len = *hello.get(pos)? as usize;
    pos += 1 + session_id_len;

    // Cipher suites: length(2) + data
    let cipher_len = u16::from_be_bytes([*hello.get(pos)?, *hello.get(pos + 1)?]) as usize;
    pos += 2 + cipher_len;

    // Compression methods: length(1) + data
    let comp_len = *hello.get(pos)? as usize;
    pos += 1 + comp_len;

    // Extensions: length(2) + data
    if pos + 2 > hello.len() {
        return None; // No extensions
    }
    let ext_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + ext_len;

    // Walk extensions looking for server_name (type 0x0000).
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([hello[pos], hello[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([hello[pos + 2], hello[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // server_name extension
            return parse_server_name(hello.get(pos..pos + ext_data_len)?);
        }

        pos += ext_data_len;
    }

    None
}

/// Parse the server_name extension data to extract the hostname.
fn parse_server_name(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }

    // Server name list: length(2) + entries
    let _list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut pos = 2;

    while pos + 3 <= data.len() {
        let name_type = data[pos];
        let name_len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
        pos += 3;

        if name_type == 0 {
            // type 0 = hostname
            let name_bytes = data.get(pos..pos + name_len)?;
            return String::from_utf8(name_bytes.to_vec()).ok();
        }

        pos += name_len;
    }

    None
}

/// Read a 3-byte big-endian integer.
fn u24_to_usize(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 3 {
        return None;
    }
    Some(((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | (bytes[2] as usize))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal TLS ClientHello with the given SNI hostname.
    fn build_client_hello(hostname: &str) -> Vec<u8> {
        let name_bytes = hostname.as_bytes();

        // server_name extension data
        let mut sni_ext = Vec::new();
        // server name list length
        let list_len = (3 + name_bytes.len()) as u16;
        sni_ext.extend_from_slice(&list_len.to_be_bytes());
        sni_ext.push(0); // type = hostname
        sni_ext.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name_bytes);

        // Extensions block
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes()); // ext type = server_name
        extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext);

        // ClientHello body
        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]); // version TLS 1.2
        hello.extend_from_slice(&[0u8; 32]); // random
        hello.push(0); // session_id length = 0
        hello.extend_from_slice(&2u16.to_be_bytes()); // cipher suites length
        hello.extend_from_slice(&[0x00, 0x2f]); // one cipher suite
        hello.push(1); // compression methods length
        hello.push(0); // null compression
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        // Handshake header
        let mut handshake = Vec::new();
        handshake.push(1); // ClientHello
        let hello_len = hello.len() as u32;
        handshake.push((hello_len >> 16) as u8);
        handshake.push((hello_len >> 8) as u8);
        handshake.push(hello_len as u8);
        handshake.extend_from_slice(&hello);

        // TLS record header
        let mut record = Vec::new();
        record.push(22); // content type = Handshake
        record.extend_from_slice(&[0x03, 0x01]); // version TLS 1.0 (record layer)
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        record
    }

    #[test]
    fn extract_sni_from_client_hello() {
        let data = build_client_hello("github.com");
        assert_eq!(
            extract_sni(&data),
            Some("github.com".to_string()),
            "should extract SNI from well-formed ClientHello"
        );
    }

    #[test]
    fn extract_sni_long_hostname() {
        let data = build_client_hello("very.deep.subdomain.example.co.uk");
        assert_eq!(
            extract_sni(&data),
            Some("very.deep.subdomain.example.co.uk".to_string()),
        );
    }

    #[test]
    fn no_sni_in_non_tls() {
        assert_eq!(extract_sni(b"GET / HTTP/1.1\r\n"), None);
    }

    #[test]
    fn no_sni_in_empty() {
        assert_eq!(extract_sni(&[]), None);
    }

    #[test]
    fn no_sni_in_truncated() {
        let data = build_client_hello("github.com");
        // Truncate to just the record header
        assert_eq!(extract_sni(&data[..5]), None);
    }
}
