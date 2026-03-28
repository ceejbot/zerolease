//! Typed client for the zerolease vault server.
//!
//! [`VaultClient`] connects to any [`VaultConnector`] implementation,
//! performs the protocol version handshake, and provides typed methods
//! for all eight protocol operations. The caller works with Rust types
//! throughout — no JSON, base64, or request IDs.

use base64::Engine;
use serde::de::DeserializeOwned;
use tokio::io::{ReadHalf, WriteHalf};
use uuid::Uuid;

use crate::audit::RevocationReason;
use crate::error::{Error, Result};
use crate::lease::LeaseGrant;
use crate::protocol::frame::{read_frame, write_frame};
use crate::protocol::{
    AccessSecretRequest, AccessSecretResponse, ClientHello, DeleteSecretRequest, ErrorPayload, ListSecretsResponse,
    RenewLeaseRequest, Request, RequestLeaseRequest, Response, RevokeAllForAgentRequest, RevokeAllForAgentResponse,
    RevokeLeaseRequest, ServerHello, StoreSecretRequest, methods,
};
use crate::store::{SecretKind, SecretMetadata};
use crate::transport::VaultConnector;

/// A client that communicates with a zerolease vault server over any
/// [`VaultConnector`] transport.
///
/// The client holds a split async stream and sends length-prefixed,
/// JSON-encoded request/response frames after completing a version
/// handshake on connection.
pub struct VaultClient<C: VaultConnector> {
    reader: ReadHalf<C::Stream>,
    writer: WriteHalf<C::Stream>,
}

impl<C: VaultConnector> VaultClient<C> {
    /// Connect to a vault server via the given connector.
    ///
    /// Performs the protocol handshake by sending a [`ClientHello`] and
    /// reading the [`ServerHello`] response. Returns an error if the
    /// handshake is rejected or the transport fails.
    pub async fn connect(connector: &C) -> Result<Self> {
        let stream = connector.connect().await?;
        let (mut reader, mut writer) = tokio::io::split(stream);

        let hello = ClientHello::new();
        let hello_bytes =
            serde_json::to_vec(&hello).map_err(|e| Error::Transport(format!("failed to serialize hello: {e}")))?;
        write_frame(&mut writer, &hello_bytes).await?;

        let resp_bytes = read_frame(&mut reader).await?;
        let server_hello: ServerHello =
            serde_json::from_slice(&resp_bytes).map_err(|e| Error::Transport(format!("invalid server hello: {e}")))?;

        if !server_hello.ok {
            return Err(Error::Transport(format!(
                "handshake rejected: {}",
                server_hello.error.unwrap_or_default()
            )));
        }

        Ok(Self { reader, writer })
    }

    /// Send a request to the server and return the result value.
    ///
    /// Generates a UUID v7 request ID, serializes the request as a
    /// length-prefixed frame, reads the response frame, and either
    /// returns the result value or maps the server error to
    /// [`Error::Remote`].
    async fn request(&mut self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let request = Request {
            id: Uuid::now_v7(),
            method: method.to_string(),
            params,
        };

        let req_bytes =
            serde_json::to_vec(&request).map_err(|e| Error::Transport(format!("failed to serialize request: {e}")))?;
        write_frame(&mut self.writer, &req_bytes).await?;

        let resp_bytes = read_frame(&mut self.reader).await?;
        let response: Response =
            serde_json::from_slice(&resp_bytes).map_err(|e| Error::Transport(format!("invalid response: {e}")))?;

        if response.ok {
            Ok(response.result.unwrap_or(serde_json::json!({})))
        } else {
            let payload = response.error.unwrap_or_else(|| ErrorPayload {
                code: "unknown".to_string(),
                message: "server returned an error with no payload".to_string(),
            });
            Err(Error::Remote {
                code: payload.code,
                message: payload.message,
            })
        }
    }

    /// Deserialize a JSON value into a concrete response type.
    ///
    /// Used by typed client methods to convert the raw `serde_json::Value`
    /// returned by [`request`](Self::request) into the expected type.
    fn parse_result<T: DeserializeOwned>(value: serde_json::Value) -> Result<T> {
        serde_json::from_value(value).map_err(|e| Error::Transport(format!("failed to parse response: {e}")))
    }

    /// Store a new secret in the vault.
    pub async fn store_secret(
        &mut self,
        name: &str,
        plaintext: &[u8],
        kind: SecretKind,
        description: Option<String>,
    ) -> Result<SecretMetadata> {
        let params = StoreSecretRequest {
            name: name.to_string(),
            plaintext: base64::engine::general_purpose::STANDARD.encode(plaintext),
            kind: serde_json::to_value(&kind)
                .map_err(|e| Error::Transport(format!("failed to serialize kind: {e}")))?,
            description,
        };
        let result = self
            .request(
                methods::STORE_SECRET,
                serde_json::to_value(&params)
                    .map_err(|e| Error::Transport(format!("failed to serialize params: {e}")))?,
            )
            .await?;
        Self::parse_result(result)
    }

    /// Request a lease for a secret.
    pub async fn request_lease(&mut self, agent: &str, secret_name: &str, domain: &str) -> Result<LeaseGrant> {
        let params = RequestLeaseRequest {
            agent: agent.to_string(),
            secret_name: secret_name.to_string(),
            domain: domain.to_string(),
        };
        let result = self
            .request(
                methods::REQUEST_LEASE,
                serde_json::to_value(&params)
                    .map_err(|e| Error::Transport(format!("failed to serialize params: {e}")))?,
            )
            .await?;
        Self::parse_result(result)
    }

    /// Access a secret using a lease. Returns the decrypted secret bytes.
    pub async fn access_secret(&mut self, lease_id: Uuid, target_domain: &str) -> Result<Vec<u8>> {
        let params = AccessSecretRequest {
            lease_id,
            target_domain: target_domain.to_string(),
        };
        let result = self
            .request(
                methods::ACCESS_SECRET,
                serde_json::to_value(&params)
                    .map_err(|e| Error::Transport(format!("failed to serialize params: {e}")))?,
            )
            .await?;
        let resp: AccessSecretResponse = Self::parse_result(result)?;
        base64::engine::general_purpose::STANDARD
            .decode(&resp.secret)
            .map_err(|e| Error::Transport(format!("invalid base64 in server response: {e}")))
    }

    /// Revoke a specific lease.
    pub async fn revoke_lease(&mut self, lease_id: Uuid, reason: RevocationReason) -> Result<()> {
        let params = RevokeLeaseRequest {
            lease_id,
            reason: serde_json::to_value(&reason)
                .map_err(|e| Error::Transport(format!("failed to serialize reason: {e}")))?,
        };
        self.request(
            methods::REVOKE_LEASE,
            serde_json::to_value(&params).map_err(|e| Error::Transport(format!("failed to serialize params: {e}")))?,
        )
        .await?;
        Ok(())
    }

    /// Revoke all active leases for an agent. Returns the number revoked.
    pub async fn revoke_all_for_agent(&mut self, agent: &str) -> Result<usize> {
        let params = RevokeAllForAgentRequest {
            agent: agent.to_string(),
        };
        let result = self
            .request(
                methods::REVOKE_ALL_FOR_AGENT,
                serde_json::to_value(&params)
                    .map_err(|e| Error::Transport(format!("failed to serialize params: {e}")))?,
            )
            .await?;
        let resp: RevokeAllForAgentResponse = Self::parse_result(result)?;
        Ok(resp.revoked_count)
    }

    /// List all stored secret metadata.
    pub async fn list_secrets(&mut self) -> Result<Vec<SecretMetadata>> {
        let result = self.request(methods::LIST_SECRETS, serde_json::json!({})).await?;
        let resp: ListSecretsResponse = Self::parse_result(result)?;
        resp.secrets
            .into_iter()
            .map(|v| {
                serde_json::from_value(v).map_err(|e| Error::Transport(format!("failed to parse secret metadata: {e}")))
            })
            .collect()
    }

    /// Renew a lease, extending its expiration.
    pub async fn renew_lease(&mut self, lease_id: Uuid, extension_secs: i64) -> Result<LeaseGrant> {
        let params = RenewLeaseRequest {
            lease_id,
            extension_secs,
        };
        let result = self
            .request(
                methods::RENEW_LEASE,
                serde_json::to_value(&params)
                    .map_err(|e| Error::Transport(format!("failed to serialize params: {e}")))?,
            )
            .await?;
        Self::parse_result(result)
    }

    /// Delete a secret and revoke all its active leases.
    pub async fn delete_secret(&mut self, name: &str) -> Result<()> {
        let params = DeleteSecretRequest { name: name.to_string() };
        self.request(
            methods::DELETE_SECRET,
            serde_json::to_value(&params).map_err(|e| Error::Transport(format!("failed to serialize params: {e}")))?,
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
#[cfg(feature = "sqlite")]
mod tests {
    use std::sync::Arc;

    use tempfile::TempDir;
    use tokio::task::JoinHandle;
    use zerolease_store_rusqlite::RusqliteStore;

    use super::*;
    use crate::audit::*;
    use crate::auth::AllowAllAdmin;
    use crate::keysource::env::EnvVarSource;
    use crate::lease::LeaseTerms;
    use crate::policy::{AgentPattern, PolicyConfig, PolicyEngine, PolicyGrant, SecretPattern};
    use crate::server::VaultServer;
    use crate::store::{CipherAlgorithm, SecretKind};
    use crate::transport::uds::{UdsConnector, UdsListener};
    use crate::types::{AgentId, DomainScope, LeaseId, SecretName};

    struct NoopAuditLog;

    #[async_trait::async_trait]
    impl AuditLog for NoopAuditLog {
        async fn record(&self, _: AuditEntry) -> Result<()> {
            Ok(())
        }
        async fn query_by_agent(&self, _: &AgentId, _: usize) -> Result<Vec<AuditEntry>> {
            Ok(vec![])
        }
        async fn query_by_secret(&self, _: &SecretName, _: usize) -> Result<Vec<AuditEntry>> {
            Ok(vec![])
        }
        async fn query_by_lease(&self, _: &LeaseId) -> Result<Vec<AuditEntry>> {
            Ok(vec![])
        }
    }

    /// Spin up a vault + server + client. Returns the client, the server
    /// JoinHandle, and temp dir (must be kept alive).
    async fn setup(
        env_var: &str,
        grants: Vec<PolicyGrant>,
    ) -> (VaultClient<UdsConnector>, JoinHandle<Result<()>>, TempDir) {
        // SAFETY: tests run single-threaded via --test-threads=1
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var(env_var, "aa".repeat(32))
        };

        let dir = TempDir::new().expect("failed to create temp directory for test");
        let sock_path = dir.path().join("vault.sock");
        let db_path = dir.path().join("secrets.db");

        let key_source = EnvVarSource::new(env_var);
        let store = RusqliteStore::new(&db_path)
            .await
            .expect("failed to initialize SQLite store");
        let audit = NoopAuditLog;
        let policy = PolicyEngine::new(PolicyConfig {
            default_lease_terms: LeaseTerms::default_short(),
            grants,
        });

        let vault = Arc::new(crate::vault::Vault::new(
            key_source,
            store,
            audit,
            policy,
            CipherAlgorithm::Aes256Gcm,
        ));
        vault.initialize().await.expect("vault initialization should succeed");

        let listener = UdsListener::bind(&sock_path).expect("failed to bind UDS listener");
        let server = VaultServer::new(Arc::clone(&vault), listener, Arc::new(AllowAllAdmin));
        let handle = tokio::spawn(async move { server.serve().await });

        // Small delay to let the server start accepting
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let connector = UdsConnector::new(&sock_path);
        let client = VaultClient::connect(&connector)
            .await
            .expect("client failed to connect to vault server");

        (client, handle, dir)
    }

    fn default_grants() -> Vec<PolicyGrant> {
        vec![PolicyGrant {
            agent: AgentPattern::Exact(AgentId::new("test-agent")),
            secret: SecretPattern::Exact(SecretName::new("test-token")),
            allowed_domains: vec![DomainScope::new("api.example.com")],
            lease_terms: None,
        }]
    }

    fn renewable_grants() -> Vec<PolicyGrant> {
        vec![PolicyGrant {
            agent: AgentPattern::Exact(AgentId::new("test-agent")),
            secret: SecretPattern::Exact(SecretName::new("test-token")),
            allowed_domains: vec![DomainScope::new("api.example.com")],
            lease_terms: Some(LeaseTerms::workflow()),
        }]
    }

    #[tokio::test]
    async fn connect_and_handshake() {
        let (client, handle, _dir) = setup("ZEROLEASE_CLIENT_TEST_1", default_grants()).await;
        drop(client);
        handle.abort();
    }

    #[tokio::test]
    async fn store_and_list() {
        let (mut client, handle, _dir) = setup("ZEROLEASE_CLIENT_TEST_2", default_grants()).await;

        let meta = client
            .store_secret("test-token", b"secret-value", SecretKind::ApiKey, None)
            .await
            .expect("store_secret should succeed");
        assert_eq!(meta.name, SecretName::new("test-token"));

        let list = client.list_secrets().await.expect("list_secrets should succeed");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, SecretName::new("test-token"));

        handle.abort();
    }

    #[tokio::test]
    async fn full_lease_cycle() {
        let (mut client, handle, _dir) = setup("ZEROLEASE_CLIENT_TEST_3", default_grants()).await;

        client
            .store_secret("test-token", b"my-api-key", SecretKind::ApiKey, None)
            .await
            .expect("store_secret should succeed");

        let grant = client
            .request_lease("test-agent", "test-token", "api.example.com")
            .await
            .expect("request_lease should succeed");

        let secret_bytes = client
            .access_secret(*grant.lease_id.as_uuid(), "api.example.com")
            .await
            .expect("access_secret should succeed");

        assert_eq!(secret_bytes, b"my-api-key");

        handle.abort();
    }

    #[tokio::test]
    async fn revoke_lease_then_access_fails() {
        let (mut client, handle, _dir) = setup("ZEROLEASE_CLIENT_TEST_4", default_grants()).await;

        client
            .store_secret("test-token", b"value", SecretKind::ApiKey, None)
            .await
            .expect("store_secret should succeed");
        let grant = client
            .request_lease("test-agent", "test-token", "api.example.com")
            .await
            .expect("request_lease should succeed");

        client
            .revoke_lease(*grant.lease_id.as_uuid(), RevocationReason::AdminRevoked)
            .await
            .expect("revoke_lease should succeed");

        let result = client.access_secret(*grant.lease_id.as_uuid(), "api.example.com").await;
        assert!(result.is_err());

        handle.abort();
    }

    #[tokio::test]
    async fn revoke_all_for_agent() {
        let (mut client, handle, _dir) = setup("ZEROLEASE_CLIENT_TEST_5", default_grants()).await;

        client
            .store_secret("test-token", b"value", SecretKind::ApiKey, None)
            .await
            .expect("store_secret should succeed");
        client
            .request_lease("test-agent", "test-token", "api.example.com")
            .await
            .expect("request_lease should succeed");

        let count = client
            .revoke_all_for_agent("test-agent")
            .await
            .expect("revoke_all_for_agent should succeed");
        assert!(count >= 1);

        handle.abort();
    }

    #[tokio::test]
    async fn delete_secret_clears_list() {
        let (mut client, handle, _dir) = setup("ZEROLEASE_CLIENT_TEST_6", default_grants()).await;

        client
            .store_secret("test-token", b"value", SecretKind::ApiKey, None)
            .await
            .expect("store_secret should succeed");
        client
            .delete_secret("test-token")
            .await
            .expect("delete_secret should succeed");

        let list = client.list_secrets().await.expect("list_secrets should succeed");
        assert!(list.is_empty());

        handle.abort();
    }

    #[tokio::test]
    async fn renew_lease_extends() {
        let (mut client, handle, _dir) = setup("ZEROLEASE_CLIENT_TEST_7", renewable_grants()).await;

        client
            .store_secret("test-token", b"value", SecretKind::ApiKey, None)
            .await
            .expect("store_secret should succeed");
        let grant = client
            .request_lease("test-agent", "test-token", "api.example.com")
            .await
            .expect("request_lease should succeed");

        let renewed = client
            .renew_lease(*grant.lease_id.as_uuid(), 3600)
            .await
            .expect("renew_lease should succeed");
        assert_eq!(renewed.lease_id, grant.lease_id);

        handle.abort();
    }

    #[tokio::test]
    async fn error_mapping_remote() {
        let (mut client, handle, _dir) = setup("ZEROLEASE_CLIENT_TEST_8", default_grants()).await;

        // Request lease for a secret that doesn't exist
        let result = client
            .request_lease("test-agent", "nonexistent", "api.example.com")
            .await;
        assert!(result.is_err());

        if let Err(Error::Remote { code, .. }) = result {
            assert_eq!(code, "access_denied");
        } else {
            panic!("expected Error::Remote, got {:?}", result);
        }

        handle.abort();
    }
}
