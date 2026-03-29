//! Git credential helper protocol implementation.
//!
//! When configured as a git credential helper, git calls this binary
//! with `get`, `store`, or `erase` as the operation and sends the
//! request on stdin. This module implements that protocol.
//!
//! The `get` operation:
//! 1. Parses `protocol=...\nhost=...\n` from stdin
//! 2. Looks up the vault secret name from the host mapping
//! 3. Connects to the vault and acquires a lease for that domain
//! 4. Prints `username=...\npassword=...\n` to stdout
//!
//! The `store` and `erase` operations are no-ops (the vault manages
//! credential lifecycle, not git).

use std::collections::HashMap;
use std::io::{self, BufRead, Write};

/// Parsed git credential request from stdin.
#[derive(Debug, Default)]
pub struct CredentialRequest {
    pub protocol: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub username: Option<String>,
}

impl CredentialRequest {
    /// Parse a git credential request from a reader.
    ///
    /// The format is `key=value` lines terminated by a blank line or EOF.
    pub fn parse(reader: &mut impl BufRead) -> io::Result<Self> {
        let mut req = Self::default();
        let mut line = String::new();

        loop {
            line.clear();
            let bytes = reader.read_line(&mut line)?;
            if bytes == 0 || line.trim().is_empty() {
                break;
            }
            let trimmed = line.trim();
            if let Some((key, value)) = trimmed.split_once('=') {
                match key {
                    "protocol" => req.protocol = Some(value.to_string()),
                    "host" => req.host = Some(value.to_string()),
                    "path" => req.path = Some(value.to_string()),
                    "username" => req.username = Some(value.to_string()),
                    _ => {} // ignore unknown keys per git spec
                }
            }
        }

        Ok(req)
    }
}

/// Write a git credential response to a writer.
pub fn write_credential(writer: &mut impl Write, username: &str, password: &str) -> io::Result<()> {
    writeln!(writer, "username={username}")?;
    writeln!(writer, "password={password}")?;
    writeln!(writer)?; // blank line terminates
    writer.flush()
}

/// Run the `get` operation: look up the host in the map, connect to
/// the vault, acquire a credential, and write it to stdout.
///
/// Returns `Ok(true)` if a credential was written, `Ok(false)` if
/// the host wasn't in the map (git will try other helpers).
pub async fn handle_get(
    request: &CredentialRequest,
    host_map: &HashMap<String, (String, String)>,
    vault_addr: std::net::SocketAddr,
    token: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let host = match &request.host {
        Some(h) => h.as_str(),
        None => return Ok(false),
    };

    let (secret_name, target_domain) = match host_map.get(host) {
        Some((s, d)) => (s.as_str(), d.as_str()),
        None => return Ok(false), // not our host, let git try other helpers
    };

    // Connect to vault.
    let connector = zerolease::transport::tcp::TcpConnector::new(vault_addr, token);
    let mut client = zerolease::client::VaultClient::connect_with_token(&connector, token).await?;

    // Lease and access.
    let grant = client
        .request_lease("credential-helper", secret_name, target_domain)
        .await?;
    let secret_bytes = client
        .access_secret(*grant.lease_id.as_uuid(), target_domain)
        .await?;
    let secret = String::from_utf8(secret_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "secret is not UTF-8"))?;

    // Write credential to stdout.
    let mut stdout = io::stdout().lock();
    write_credential(&mut stdout, "x-access-token", &secret)?;

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_credential_request() {
        let input = "protocol=https\nhost=github.com\npath=/ceejbot/zerolease\n\n";
        let mut reader = io::Cursor::new(input);
        let req = CredentialRequest::parse(&mut reader).expect("should parse");

        assert_eq!(req.protocol.as_deref(), Some("https"));
        assert_eq!(req.host.as_deref(), Some("github.com"));
        assert_eq!(req.path.as_deref(), Some("/ceejbot/zerolease"));
        assert_eq!(req.username, None);
    }

    #[test]
    fn parse_minimal_request() {
        let input = "host=gitlab.com\n\n";
        let mut reader = io::Cursor::new(input);
        let req = CredentialRequest::parse(&mut reader).expect("should parse");

        assert_eq!(req.host.as_deref(), Some("gitlab.com"));
        assert_eq!(req.protocol, None);
    }

    #[test]
    fn parse_eof_terminated() {
        // git may not send trailing blank line
        let input = "protocol=https\nhost=github.com";
        let mut reader = io::Cursor::new(input);
        let req = CredentialRequest::parse(&mut reader).expect("should parse");

        assert_eq!(req.host.as_deref(), Some("github.com"));
    }

    #[test]
    fn parse_unknown_keys_ignored() {
        let input = "protocol=https\nhost=github.com\nfuture_key=whatever\n\n";
        let mut reader = io::Cursor::new(input);
        let req = CredentialRequest::parse(&mut reader).expect("should parse");

        assert_eq!(req.host.as_deref(), Some("github.com"));
    }

    #[test]
    fn write_credential_format() {
        let mut buf = Vec::new();
        write_credential(&mut buf, "x-access-token", "ghp_abc123")
            .expect("should write");
        let output = String::from_utf8(buf).expect("should be utf8");

        assert!(output.contains("username=x-access-token\n"));
        assert!(output.contains("password=ghp_abc123\n"));
    }
}
