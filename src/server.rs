//! VaultServer: accepts connections, performs handshake, and dispatches
//! protocol requests to the underlying `Vault`.

use std::sync::Arc;

use base64::Engine;
use uuid::Uuid;

use crate::audit::{AuditLog, RevocationReason};
use crate::auth::{Authenticator, ConnectionIdentity, Role};
use crate::keysource::KeySource;
use crate::protocol::frame::{read_frame, write_frame};
use crate::protocol::{
    AccessSecretRequest, AccessSecretResponse, CODE_INVALID_REQUEST, CURRENT_VERSION, ClientHello, DeleteSecretRequest,
    ListSecretsResponse, PROTOCOL_NAME, RenewLeaseRequest, Request, RequestLeaseRequest, Response,
    RevokeAllForAgentRequest, RevokeAllForAgentResponse, RevokeLeaseRequest, ServerHello, StoreSecretRequest, methods,
};
use crate::store::{SecretKind, SecretStore};
use crate::transport::{PeerIdentity, VaultListener, VaultStream};
use crate::types::{AgentId, DomainScope, LeaseId, SecretName};
use crate::vault::Vault;

/// A server that accepts connections from a [`VaultListener`] and dispatches
/// requests to a shared [`Vault`].
pub struct VaultServer<K, S, A, L>
where
    K: KeySource,
    S: SecretStore,
    A: AuditLog,
    L: VaultListener,
{
    vault: Arc<Vault<K, S, A>>,
    listener: L,
    authenticator: Arc<dyn Authenticator>,
}

impl<K, S, A, L> VaultServer<K, S, A, L>
where
    K: KeySource,
    S: SecretStore,
    A: AuditLog,
    L: VaultListener,
{
    /// Create a new server with the given vault, listener, and authenticator.
    pub fn new(vault: Arc<Vault<K, S, A>>, listener: L, authenticator: Arc<dyn Authenticator>) -> Self {
        Self {
            vault,
            listener,
            authenticator,
        }
    }

    /// Accept connections in a loop and spawn a task for each one.
    ///
    /// Returns when the listener produces an error (e.g., the socket is
    /// closed).
    pub async fn serve(&self) -> crate::error::Result<()> {
        loop {
            let (stream, peer) = self.listener.accept().await?;
            let vault = Arc::clone(&self.vault);
            let auth = Arc::clone(&self.authenticator);
            tokio::spawn(async move {
                if let Err(e) = handle_connection(vault, stream, peer, auth).await {
                    tracing::warn!(error = %e, "connection handler error");
                }
            });
        }
    }

    /// Accept connections until a shutdown signal is received.
    ///
    /// When the `shutdown` future resolves, the server stops accepting
    /// new connections and returns. Already-spawned connection tasks
    /// continue running to completion — they hold their own `Arc<Vault>`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// server.serve_with_shutdown(tokio::signal::ctrl_c().map(|_| ())).await?;
    /// ```
    pub async fn serve_with_shutdown(&self, shutdown: impl Future<Output = ()>) -> crate::error::Result<()> {
        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                result = self.listener.accept() => {
                    let (stream, peer) = result?;
                    let vault = Arc::clone(&self.vault);
                    let auth = Arc::clone(&self.authenticator);
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(vault, stream, peer, auth).await {
                            tracing::warn!(error = %e, "connection handler error");
                        }
                    });
                }
                () = &mut shutdown => {
                    tracing::info!("shutdown signal received, stopping accept loop");
                    return Ok(());
                }
            }
        }
    }
}

/// Handle a single client connection: handshake then request loop.
pub(crate) async fn handle_connection<K, S, A>(
    vault: Arc<Vault<K, S, A>>,
    stream: impl VaultStream,
    peer: PeerIdentity,
    authenticator: Arc<dyn Authenticator>,
) -> crate::error::Result<()>
where
    K: KeySource,
    S: SecretStore,
    A: AuditLog,
{
    let (mut reader, mut writer) = tokio::io::split(stream);

    // --- Handshake ---
    let hello_bytes = read_frame(&mut reader).await?;
    let hello: ClientHello = serde_json::from_slice(&hello_bytes)
        .map_err(|e| crate::error::Error::Transport(format!("invalid ClientHello: {e}")))?;

    if hello.protocol != PROTOCOL_NAME {
        let reject = ServerHello::reject(format!(
            "unknown protocol: {}; expected {PROTOCOL_NAME}",
            hello.protocol
        ));
        let bytes = serde_json::to_vec(&reject)
            .map_err(|e| crate::error::Error::Transport(format!("failed to serialize ServerHello: {e}")))?;
        write_frame(&mut writer, &bytes).await?;
        return Ok(());
    }

    if hello.version > CURRENT_VERSION {
        let reject = ServerHello::reject(format!(
            "unsupported version {}; server supports up to {CURRENT_VERSION}",
            hello.version
        ));
        let bytes = serde_json::to_vec(&reject)
            .map_err(|e| crate::error::Error::Transport(format!("failed to serialize ServerHello: {e}")))?;
        write_frame(&mut writer, &bytes).await?;
        return Ok(());
    }

    // Accept
    let accept = ServerHello::accept(hello.version);
    let bytes = serde_json::to_vec(&accept)
        .map_err(|e| crate::error::Error::Transport(format!("failed to serialize ServerHello: {e}")))?;
    write_frame(&mut writer, &bytes).await?;

    // --- Token extraction ---
    // If the client presented a token (TCP transports), hash it into
    // the PeerIdentity for audit and pass the raw value to the
    // authenticator for validation.
    let mut peer = peer;
    let token = hello.token;
    if let Some(ref t) = token {
        let hash = crate::transport::hash_token(t);
        peer.set_token_hash(hash);
    }

    // --- Authentication ---
    let identity = match authenticator.authenticate(&peer, token.as_deref()).await {
        Some(id) => {
            tracing::info!(
                role = ?id.role,
                label = %id.label,
                peer = %peer,
                "connection authenticated"
            );
            id
        }
        None => {
            tracing::warn!(peer = %peer, "connection rejected by authenticator");
            return Ok(());
        }
    };

    // --- Request loop ---
    loop {
        let frame = match read_frame(&mut reader).await {
            Ok(f) => f,
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("unexpected EOF") {
                    // Clean disconnect
                    return Ok(());
                }
                // Framing error — close the connection
                let resp = Response::protocol_error(Uuid::nil(), CODE_INVALID_REQUEST, format!("frame error: {msg}"));
                let resp_bytes = serde_json::to_vec(&resp).unwrap_or_default();
                let _ = write_frame(&mut writer, &resp_bytes).await;
                return Ok(());
            }
        };

        let request: Request = match serde_json::from_slice(&frame) {
            Ok(r) => r,
            Err(e) => {
                let resp = Response::protocol_error(Uuid::nil(), CODE_INVALID_REQUEST, format!("invalid request: {e}"));
                let resp_bytes = serde_json::to_vec(&resp).unwrap_or_default();
                let _ = write_frame(&mut writer, &resp_bytes).await;
                continue;
            }
        };

        let response = dispatch(&vault, request, &peer, &identity).await;

        let resp_bytes = serde_json::to_vec(&response)
            .map_err(|e| crate::error::Error::Transport(format!("failed to serialize response: {e}")))?;
        write_frame(&mut writer, &resp_bytes).await?;
    }
}

/// Parse request params into a typed struct, returning a protocol error on
/// failure.
macro_rules! parse_params {
    ($request:expr, $type:ty) => {
        match serde_json::from_value::<$type>($request.params) {
            Ok(r) => r,
            Err(e) => {
                return Response::protocol_error($request.id, CODE_INVALID_REQUEST, format!("invalid params: {e}"));
            }
        }
    };
}

/// Serialize a vault result into a JSON response.
macro_rules! json_response {
    ($id:expr, $result:expr) => {
        match $result {
            Ok(value) => match serde_json::to_value(value) {
                Ok(v) => Response::success($id, v),
                Err(e) => Response::protocol_error($id, CODE_INVALID_REQUEST, format!("serialization failed: {e}")),
            },
            Err(e) => Response::from_error($id, &e),
        }
    };
}

/// Dispatch a single [`Request`] to the appropriate vault method.
/// Methods that require admin role.
const ADMIN_METHODS: &[&str] = &[methods::STORE_SECRET, methods::DELETE_SECRET, methods::LIST_SECRETS];

pub(crate) async fn dispatch<K, S, A>(
    vault: &Vault<K, S, A>,
    request: Request,
    peer: &PeerIdentity,
    identity: &ConnectionIdentity,
) -> Response
where
    K: KeySource,
    S: SecretStore,
    A: AuditLog,
{
    // --- Role enforcement ---
    let method = request.method.as_str();

    if ADMIN_METHODS.contains(&method) && identity.role != Role::Admin {
        return Response::from_error(
            request.id,
            &crate::error::Error::AccessDenied {
                agent: identity
                    .agent_id
                    .clone()
                    .unwrap_or_else(|| AgentId::new(&identity.label)),
                secret: SecretName::new(method),
                domain: DomainScope::new("admin"),
            },
        );
    }

    // --- Resolve effective agent identity ---
    // Agent: use bound identity (ignore request). Orchestrator: use request
    // (trusted). Admin: use request (admin can do anything).
    let resolve_agent = |requested: &str| -> AgentId {
        match &identity.role {
            Role::Agent => identity.agent_id.clone().unwrap_or_else(|| AgentId::new(requested)),
            Role::Orchestrator | Role::Admin => AgentId::new(requested),
        }
    };

    let id = request.id;

    match method {
        methods::STORE_SECRET => {
            let req = parse_params!(request, StoreSecretRequest);

            let plaintext = match base64::engine::general_purpose::STANDARD.decode(&req.plaintext) {
                Ok(b) => b,
                Err(e) => {
                    return Response::protocol_error(id, CODE_INVALID_REQUEST, format!("invalid base64: {e}"));
                }
            };

            let kind: SecretKind = match serde_json::from_value(req.kind) {
                Ok(k) => k,
                Err(e) => {
                    return Response::protocol_error(id, CODE_INVALID_REQUEST, format!("invalid kind: {e}"));
                }
            };

            json_response!(
                id,
                vault
                    .store_secret(&SecretName::new(&req.name), &plaintext, kind, req.description, peer)
                    .await
            )
        }

        methods::REQUEST_LEASE => {
            let req = parse_params!(request, RequestLeaseRequest);
            let agent = resolve_agent(&req.agent);
            json_response!(
                id,
                vault
                    .request_lease(
                        &agent,
                        &SecretName::new(&req.secret_name),
                        &DomainScope::new(&req.domain),
                        peer
                    )
                    .await
            )
        }

        methods::ACCESS_SECRET => {
            let req = parse_params!(request, AccessSecretRequest);
            match vault
                .access_secret(&LeaseId::from_uuid(req.lease_id), &req.target_domain, peer)
                .await
            {
                Ok(guard) => {
                    let secret = guard.expose(|s| base64::engine::general_purpose::STANDARD.encode(s));
                    json_response!(id, Ok::<_, crate::error::Error>(AccessSecretResponse { secret }))
                }
                Err(e) => Response::from_error(id, &e),
            }
        }

        methods::REVOKE_LEASE => {
            let req = parse_params!(request, RevokeLeaseRequest);
            let reason: RevocationReason = match serde_json::from_value(req.reason) {
                Ok(r) => r,
                Err(e) => {
                    return Response::protocol_error(id, CODE_INVALID_REQUEST, format!("invalid reason: {e}"));
                }
            };

            match vault
                .revoke_lease(&LeaseId::from_uuid(req.lease_id), reason, peer)
                .await
            {
                Ok(()) => Response::success(id, serde_json::json!({})),
                Err(e) => Response::from_error(id, &e),
            }
        }

        methods::REVOKE_ALL_FOR_AGENT => {
            let req = parse_params!(request, RevokeAllForAgentRequest);
            let agent = resolve_agent(&req.agent);
            json_response!(
                id,
                vault
                    .revoke_all_for_agent(&agent, peer)
                    .await
                    .map(|count| { RevokeAllForAgentResponse { revoked_count: count } })
            )
        }

        methods::LIST_SECRETS => {
            json_response!(
                id,
                vault.list_secrets().await.map(|secrets| {
                    let values: Vec<serde_json::Value> = secrets
                        .into_iter()
                        .filter_map(|s| serde_json::to_value(s).ok())
                        .collect();
                    ListSecretsResponse { secrets: values }
                })
            )
        }

        methods::RENEW_LEASE => {
            let req = parse_params!(request, RenewLeaseRequest);
            json_response!(
                id,
                vault
                    .renew_lease(&LeaseId::from_uuid(req.lease_id), req.extension_secs, peer)
                    .await
            )
        }

        methods::DELETE_SECRET => {
            let req = parse_params!(request, DeleteSecretRequest);
            match vault.delete_secret(&SecretName::new(&req.name), peer).await {
                Ok(()) => Response::success(id, serde_json::json!({})),
                Err(e) => Response::from_error(id, &e),
            }
        }

        _ => Response::protocol_error(id, CODE_INVALID_REQUEST, format!("unknown method: {}", request.method)),
    }
}

#[cfg(test)]
#[cfg(feature = "sqlite")]
mod tests {
    use std::sync::Arc;

    use base64::Engine;
    use tempfile::NamedTempFile;
    use uuid::Uuid;
    use zerolease_store_rusqlite::RusqliteStore;

    use super::*;
    use crate::audit::*;
    use crate::auth::{AllowAllAdmin, ConnectionIdentity, Role};
    use crate::error::Result;
    use crate::keysource::env::EnvVarSource;
    use crate::lease::LeaseTerms;
    use crate::policy::{AgentPattern, PolicyConfig, PolicyEngine, PolicyGrant, SecretPattern};
    use crate::protocol::{Request, methods};
    use crate::store::CipherAlgorithm;
    use crate::transport::PeerIdentity;
    use crate::types::{AgentId, DomainScope, LeaseId, SecretName};
    use crate::vault::Vault;

    /// A no-op audit log that discards all events. For testing only.
    struct NoopAuditLog;

    #[async_trait::async_trait]
    impl AuditLog for NoopAuditLog {
        async fn record(&self, _entry: AuditEntry) -> Result<()> {
            Ok(())
        }

        async fn query_by_agent(&self, _agent: &AgentId, _limit: usize) -> Result<Vec<AuditEntry>> {
            Ok(vec![])
        }

        async fn query_by_secret(&self, _secret: &SecretName, _limit: usize) -> Result<Vec<AuditEntry>> {
            Ok(vec![])
        }

        async fn query_by_lease(&self, _lease: &LeaseId) -> Result<Vec<AuditEntry>> {
            Ok(vec![])
        }
    }

    /// Create an initialized test vault with a policy grant for "test-agent".
    /// Uses a unique env var name and a temp SQLite file.
    /// Returns (Arc<Vault>, NamedTempFile) — keep the temp file alive for the
    /// test duration.
    async fn test_vault(
        env_var: &str,
        grants: Vec<PolicyGrant>,
    ) -> (Arc<Vault<EnvVarSource, RusqliteStore, NoopAuditLog>>, NamedTempFile) {
        // SAFETY: tests run single-threaded via --test-threads=1
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var(env_var, "ab".repeat(32))
        };

        let key_source = EnvVarSource::new(env_var);
        let tmp = NamedTempFile::new().expect("should create temp file");
        let store = RusqliteStore::new(tmp.path()).await.expect("should create store");
        let audit = NoopAuditLog;

        let policy = PolicyEngine::new(PolicyConfig {
            default_lease_terms: LeaseTerms::default_short(),
            grants,
        });

        let vault = Arc::new(Vault::new(key_source, store, audit, policy, CipherAlgorithm::Aes256Gcm));
        vault.initialize().await.expect("should initialize vault");
        (vault, tmp)
    }

    /// Default grant allowing test-agent access to any secret on
    /// api.example.com.
    fn default_grant() -> PolicyGrant {
        PolicyGrant {
            agent: AgentPattern::Exact(AgentId::new("test-agent")),
            secret: SecretPattern::Any,
            allowed_domains: vec![DomainScope::new("api.example.com")],
            lease_terms: None,
        }
    }

    /// A grant with renewable (workflow) lease terms.
    fn renewable_grant() -> PolicyGrant {
        PolicyGrant {
            agent: AgentPattern::Exact(AgentId::new("test-agent")),
            secret: SecretPattern::Any,
            allowed_domains: vec![DomainScope::new("api.example.com")],
            lease_terms: Some(LeaseTerms::workflow()),
        }
    }

    fn admin_identity() -> ConnectionIdentity {
        ConnectionIdentity {
            role: Role::Admin,
            agent_id: None,
            label: "test-admin".to_string(),
        }
    }

    /// Build a store_secret Request for the given name and plaintext.
    fn store_request(name: &str, plaintext: &[u8]) -> Request {
        Request {
            id: Uuid::now_v7(),
            method: methods::STORE_SECRET.to_string(),
            params: serde_json::json!({
                "name": name,
                "plaintext": base64::engine::general_purpose::STANDARD.encode(plaintext),
                "kind": "ApiKey",
            }),
        }
    }

    /// Build a request_lease Request.
    fn lease_request(secret_name: &str) -> Request {
        Request {
            id: Uuid::now_v7(),
            method: methods::REQUEST_LEASE.to_string(),
            params: serde_json::json!({
                "agent": "test-agent",
                "secret_name": secret_name,
                "domain": "api.example.com",
            }),
        }
    }

    #[tokio::test]
    async fn dispatch_store_secret() {
        let (vault, _tmp) = test_vault("ZEROLEASE_TEST_DISPATCH_1", vec![default_grant()]).await;
        let peer = PeerIdentity::Anonymous;

        let req = store_request("my-token", b"secret-value");
        let resp = dispatch(&vault, &req, &peer, &admin_identity()).await;

        assert!(resp.ok);
        let result = resp.result.expect("should get store_secret result");
        assert_eq!(result["name"], "my-token");
    }

    #[tokio::test]
    async fn dispatch_request_lease() {
        let (vault, _tmp) = test_vault("ZEROLEASE_TEST_DISPATCH_2", vec![default_grant()]).await;
        let peer = PeerIdentity::Anonymous;

        // Store a secret first
        let store_req = store_request("my-token", b"secret-value");
        dispatch(&vault, &store_req, &peer, &admin_identity()).await;

        // Request a lease
        let req = lease_request("my-token");
        let resp = dispatch(&vault, &req, &peer, &admin_identity()).await;

        assert!(resp.ok);
        let result = resp.result.expect("should get request_lease result");
        assert!(result.get("lease_id").is_some());
    }

    #[tokio::test]
    async fn dispatch_access_secret() {
        let (vault, _tmp) = test_vault("ZEROLEASE_TEST_DISPATCH_3", vec![default_grant()]).await;
        let peer = PeerIdentity::Anonymous;

        // Store
        let plaintext = b"super-secret-api-key";
        dispatch(&vault, &store_request("my-token", plaintext), &peer, &admin_identity()).await;

        // Lease
        let lease_resp = dispatch(&vault, &lease_request("my-token"), &peer, &admin_identity()).await;
        let lease_result = lease_resp.result.expect("should get lease result");
        let lease_id = lease_result["lease_id"]
            .as_str()
            .expect("should get lease_id as string")
            .to_string();

        // Access
        let access_req = Request {
            id: Uuid::now_v7(),
            method: methods::ACCESS_SECRET.to_string(),
            params: serde_json::json!({
                "lease_id": lease_id,
                "target_domain": "api.example.com",
            }),
        };
        let resp = dispatch(&vault, &access_req, &peer, &admin_identity()).await;

        assert!(resp.ok);
        let result = resp.result.expect("should get access_secret result");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(result["secret"].as_str().expect("should get secret as string"))
            .expect("should decode base64 secret");
        assert_eq!(decoded, plaintext);
    }

    #[tokio::test]
    async fn dispatch_list_secrets() {
        let (vault, _tmp) = test_vault("ZEROLEASE_TEST_DISPATCH_4", vec![default_grant()]).await;
        let peer = PeerIdentity::Anonymous;

        // Store two secrets
        dispatch(&vault, &store_request("token-a", b"val-a"), &peer, &admin_identity()).await;
        dispatch(&vault, &store_request("token-b", b"val-b"), &peer, &admin_identity()).await;

        // List
        let req = Request {
            id: Uuid::now_v7(),
            method: methods::LIST_SECRETS.to_string(),
            params: serde_json::json!({}),
        };
        let resp = dispatch(&vault, &req, &peer, &admin_identity()).await;

        assert!(resp.ok);
        let result = resp.result.expect("should get list_secrets result");
        let secrets = result["secrets"].as_array().expect("should get secrets as array");
        assert_eq!(secrets.len(), 2);
    }

    #[tokio::test]
    async fn dispatch_renew_lease() {
        let (vault, _tmp) = test_vault("ZEROLEASE_TEST_DISPATCH_5", vec![renewable_grant()]).await;
        let peer = PeerIdentity::Anonymous;

        // Store + lease
        dispatch(&vault, &store_request("my-token", b"val"), &peer, &admin_identity()).await;
        let lease_resp = dispatch(&vault, &lease_request("my-token"), &peer, &admin_identity()).await;
        let lease_result = lease_resp.result.expect("should get lease result for renewal");
        let lease_id = lease_result["lease_id"]
            .as_str()
            .expect("should get lease_id as string")
            .to_string();

        // Renew
        let req = Request {
            id: Uuid::now_v7(),
            method: methods::RENEW_LEASE.to_string(),
            params: serde_json::json!({
                "lease_id": lease_id,
                "extension_secs": 3600,
            }),
        };
        let resp = dispatch(&vault, &req, &peer, &admin_identity()).await;

        assert!(resp.ok, "renew_lease failed: {:?}", resp.error);
    }

    #[tokio::test]
    async fn dispatch_delete_secret() {
        let (vault, _tmp) = test_vault("ZEROLEASE_TEST_DISPATCH_6", vec![default_grant()]).await;
        let peer = PeerIdentity::Anonymous;

        // Store
        dispatch(&vault, &store_request("my-token", b"val"), &peer, &admin_identity()).await;

        // Delete
        let req = Request {
            id: Uuid::now_v7(),
            method: methods::DELETE_SECRET.to_string(),
            params: serde_json::json!({ "name": "my-token" }),
        };
        let resp = dispatch(&vault, &req, &peer, &admin_identity()).await;
        assert!(resp.ok);

        // Verify empty list
        let list_req = Request {
            id: Uuid::now_v7(),
            method: methods::LIST_SECRETS.to_string(),
            params: serde_json::json!({}),
        };
        let list_resp = dispatch(&vault, &list_req, &peer, &admin_identity()).await;
        assert!(list_resp.ok);
        let list_result = list_resp.result.expect("should get list_secrets result after delete");
        let secrets = list_result["secrets"]
            .as_array()
            .expect("should get secrets as array")
            .clone();
        assert!(secrets.is_empty());
    }

    #[tokio::test]
    async fn dispatch_revoke_lease() {
        let (vault, _tmp) = test_vault("ZEROLEASE_TEST_DISPATCH_7", vec![default_grant()]).await;
        let peer = PeerIdentity::Anonymous;

        // Store + lease
        dispatch(&vault, &store_request("my-token", b"val"), &peer, &admin_identity()).await;
        let lease_resp = dispatch(&vault, &lease_request("my-token"), &peer, &admin_identity()).await;
        let lease_result = lease_resp.result.expect("should get lease result for revocation");
        let lease_id = lease_result["lease_id"]
            .as_str()
            .expect("should get lease_id as string")
            .to_string();

        // Revoke
        let req = Request {
            id: Uuid::now_v7(),
            method: methods::REVOKE_LEASE.to_string(),
            params: serde_json::json!({
                "lease_id": lease_id,
                "reason": "AdminRevoked",
            }),
        };
        let resp = dispatch(&vault, &req, &peer, &admin_identity()).await;

        assert!(resp.ok, "revoke_lease failed: {:?}", resp.error);
    }

    #[tokio::test]
    async fn dispatch_revoke_all_for_agent() {
        let (vault, _tmp) = test_vault("ZEROLEASE_TEST_DISPATCH_8", vec![default_grant()]).await;
        let peer = PeerIdentity::Anonymous;

        // Store + lease
        dispatch(&vault, &store_request("my-token", b"val"), &peer, &admin_identity()).await;
        dispatch(&vault, &lease_request("my-token"), &peer, &admin_identity()).await;

        // Revoke all
        let req = Request {
            id: Uuid::now_v7(),
            method: methods::REVOKE_ALL_FOR_AGENT.to_string(),
            params: serde_json::json!({ "agent": "test-agent" }),
        };
        let resp = dispatch(&vault, &req, &peer, &admin_identity()).await;

        assert!(resp.ok);
        let result = resp.result.expect("should get revoke_all_for_agent result");
        assert!(result.get("revoked_count").is_some());
        assert!(
            result["revoked_count"]
                .as_u64()
                .expect("should get revoked_count as u64")
                >= 1
        );
    }

    #[tokio::test]
    async fn dispatch_unknown_method() {
        let (vault, _tmp) = test_vault("ZEROLEASE_TEST_DISPATCH_9", vec![default_grant()]).await;
        let peer = PeerIdentity::Anonymous;

        let req = Request {
            id: Uuid::now_v7(),
            method: "nonexistent".to_string(),
            params: serde_json::json!({}),
        };
        let resp = dispatch(&vault, &req, &peer, &admin_identity()).await;

        assert!(!resp.ok);
        let err = resp.error.expect("should get error for unknown method");
        assert_eq!(err.code, "invalid_request");
    }

    // ---------------------------------------------------------------
    // Connection handler integration tests (using tokio::io::duplex)
    // ---------------------------------------------------------------

    use tokio::io::AsyncWriteExt;

    use crate::protocol::frame::{read_frame, write_frame};

    /// Perform a successful handshake on the client side of a duplex stream.
    async fn client_handshake(client: &mut tokio::io::DuplexStream) {
        let hello = ClientHello::new();
        let bytes = serde_json::to_vec(&hello).expect("should serialize ClientHello");
        write_frame(client, &bytes).await.expect("should write handshake frame");

        let resp_bytes = read_frame(client).await.expect("should read server handshake response");
        let server_hello: ServerHello = serde_json::from_slice(&resp_bytes).expect("should deserialize ServerHello");
        assert!(server_hello.ok);
    }

    #[tokio::test]
    async fn handler_handshake_and_request() {
        let (vault, _tmp) = test_vault("ZEROLEASE_TEST_HANDLER_1", vec![default_grant()]).await;
        let (server_stream, mut client) = tokio::io::duplex(65536);

        tokio::spawn(handle_connection(
            vault,
            server_stream,
            PeerIdentity::Anonymous,
            Arc::new(AllowAllAdmin),
        ));

        // Handshake
        let hello = ClientHello::new();
        let bytes = serde_json::to_vec(&hello).expect("should serialize ClientHello");
        write_frame(&mut client, &bytes)
            .await
            .expect("should write ClientHello frame");

        let resp_bytes = read_frame(&mut client).await.expect("should read ServerHello frame");
        let server_hello: ServerHello = serde_json::from_slice(&resp_bytes).expect("should deserialize ServerHello");
        assert!(server_hello.ok);

        // store_secret request
        let req = store_request("handler-token", b"handler-secret");
        let req_bytes = serde_json::to_vec(&req).expect("should serialize store_secret request");
        write_frame(&mut client, &req_bytes)
            .await
            .expect("should write store_secret request frame");

        let resp_bytes = read_frame(&mut client)
            .await
            .expect("should read store_secret response frame");
        let resp: Response = serde_json::from_slice(&resp_bytes).expect("should deserialize store_secret response");
        assert!(resp.ok);
    }

    #[tokio::test]
    async fn handler_bad_handshake_closes() {
        let (vault, _tmp) = test_vault("ZEROLEASE_TEST_HANDLER_2", vec![default_grant()]).await;
        let (server_stream, mut client) = tokio::io::duplex(65536);

        tokio::spawn(handle_connection(
            vault,
            server_stream,
            PeerIdentity::Anonymous,
            Arc::new(AllowAllAdmin),
        ));

        // Send a ClientHello with wrong protocol
        let hello = ClientHello {
            protocol: "not-zerolease".to_string(),
            version: 1,
        };
        let bytes = serde_json::to_vec(&hello).expect("should serialize bad ClientHello");
        write_frame(&mut client, &bytes)
            .await
            .expect("should write bad ClientHello frame");

        let resp_bytes = read_frame(&mut client)
            .await
            .expect("should read rejection ServerHello");
        let server_hello: ServerHello =
            serde_json::from_slice(&resp_bytes).expect("should deserialize rejection ServerHello");
        assert!(!server_hello.ok);

        // Next read should get EOF (connection closed)
        let result = read_frame(&mut client).await;
        assert!(result.is_err());
        assert!(
            result
                .expect_err("should get EOF error after rejected handshake")
                .to_string()
                .contains("unexpected EOF")
        );
    }

    #[tokio::test]
    async fn handler_framing_error_closes() {
        let (vault, _tmp) = test_vault("ZEROLEASE_TEST_HANDLER_3", vec![default_grant()]).await;
        let (server_stream, mut client) = tokio::io::duplex(65536);

        tokio::spawn(handle_connection(
            vault,
            server_stream,
            PeerIdentity::Anonymous,
            Arc::new(AllowAllAdmin),
        ));

        // Successful handshake
        client_handshake(&mut client).await;

        // Write a 4-byte length header claiming MAX_FRAME_SIZE + 1 bytes
        let oversize_len: u32 = 1_048_577;
        client
            .write_all(&oversize_len.to_be_bytes())
            .await
            .expect("should write oversize length header");

        // Read the error response
        let resp_bytes = read_frame(&mut client)
            .await
            .expect("should read framing error response");
        let resp: Response = serde_json::from_slice(&resp_bytes).expect("should deserialize framing error response");
        assert!(!resp.ok);
        let err = resp.error.expect("should get error for framing violation");
        assert_eq!(err.code, "invalid_request");

        // Next read should get EOF
        let result = read_frame(&mut client).await;
        assert!(result.is_err());
        assert!(
            result
                .expect_err("should get EOF error after framing error")
                .to_string()
                .contains("unexpected EOF")
        );
    }

    #[tokio::test]
    async fn handler_invalid_request_continues() {
        let (vault, _tmp) = test_vault("ZEROLEASE_TEST_HANDLER_4", vec![default_grant()]).await;
        let (server_stream, mut client) = tokio::io::duplex(65536);

        tokio::spawn(handle_connection(
            vault,
            server_stream,
            PeerIdentity::Anonymous,
            Arc::new(AllowAllAdmin),
        ));

        // Successful handshake
        client_handshake(&mut client).await;

        // Send a request with unknown method
        let bad_req = Request {
            id: Uuid::now_v7(),
            method: "nonexistent".to_string(),
            params: serde_json::json!({}),
        };
        let bytes = serde_json::to_vec(&bad_req).expect("should serialize bad request");
        write_frame(&mut client, &bytes)
            .await
            .expect("should write bad request frame");

        let resp_bytes = read_frame(&mut client)
            .await
            .expect("should read error response for bad request");
        let resp: Response = serde_json::from_slice(&resp_bytes).expect("should deserialize error response");
        assert!(!resp.ok);
        let err = resp.error.expect("should get error for invalid method");
        assert_eq!(err.code, "invalid_request");

        // Connection should still be alive — send a valid request
        let req = store_request("still-alive", b"value");
        let req_bytes = serde_json::to_vec(&req).expect("should serialize follow-up request");
        write_frame(&mut client, &req_bytes)
            .await
            .expect("should write follow-up request frame");

        let resp_bytes = read_frame(&mut client)
            .await
            .expect("should read follow-up response frame");
        let resp: Response = serde_json::from_slice(&resp_bytes).expect("should deserialize follow-up response");
        assert!(resp.ok);
    }

    #[tokio::test]
    async fn dispatch_malformed_params() {
        let (vault, _tmp) = test_vault("ZEROLEASE_TEST_DISPATCH_10", vec![default_grant()]).await;
        let peer = PeerIdentity::Anonymous;

        let req = Request {
            id: Uuid::now_v7(),
            method: methods::REQUEST_LEASE.to_string(),
            params: serde_json::json!({ "agent": 123 }),
        };
        let resp = dispatch(&vault, &req, &peer, &admin_identity()).await;

        assert!(!resp.ok);
        let err = resp.error.expect("should get error for malformed params");
        assert_eq!(err.code, "invalid_request");
    }
}
