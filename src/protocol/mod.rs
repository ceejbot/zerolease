//! Wire protocol types and framing for vault client-server communication.
//!
//! The protocol uses JSON messages over length-prefixed frames. Each
//! connection begins with a version negotiation handshake, followed
//! by request-response pairs identified by UUID v7 request IDs.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::Error;

pub mod frame;

// -- Constants --

/// The protocol name used in handshake messages.
pub const PROTOCOL_NAME: &str = "zerolease";

/// The current protocol version.
pub const CURRENT_VERSION: u32 = 1;

// -- Handshake types --

/// Client hello message, sent as the first frame on a new connection.
///
/// The `token` field is used by TCP transports for authentication.
/// UDS and vsock clients omit it (transport-level identity suffices).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    pub protocol: String,
    pub version: u32,
    /// Optional authentication token for transports that lack
    /// transport-level identity (e.g., TCP). Omitted for UDS/vsock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

impl Default for ClientHello {
    fn default() -> Self {
        Self {
            protocol: PROTOCOL_NAME.to_string(),
            version: CURRENT_VERSION,
            token: None,
        }
    }
}

impl ClientHello {
    /// Create a hello for the current protocol version (no token).
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a hello with an authentication token for TCP transports.
    pub fn with_token(token: impl Into<String>) -> Self {
        Self {
            token: Some(token.into()),
            ..Self::default()
        }
    }
}

/// Server hello response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHello {
    pub protocol: String,
    pub version: u32,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ServerHello {
    /// Accept the client's version.
    pub fn accept(version: u32) -> Self {
        Self {
            protocol: PROTOCOL_NAME.to_string(),
            version,
            ok: true,
            error: None,
        }
    }

    /// Reject the client's version.
    pub fn reject(reason: impl Into<String>) -> Self {
        Self {
            protocol: PROTOCOL_NAME.to_string(),
            version: CURRENT_VERSION,
            ok: false,
            error: Some(reason.into()),
        }
    }
}

// -- Request/Response envelope --

/// A request from the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub id: Uuid,
    pub method: String,
    pub params: serde_json::Value,
}

/// A response from the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub id: Uuid,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorPayload>,
}

impl Response {
    /// Create a success response.
    pub fn success(id: Uuid, result: serde_json::Value) -> Self {
        Self {
            id,
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    /// Create an error response from a vault error.
    pub fn from_error(id: Uuid, err: &Error) -> Self {
        Self {
            id,
            ok: false,
            result: None,
            error: Some(error_to_payload(err)),
        }
    }

    /// Create an error response from a protocol-level error code and message.
    pub fn protocol_error(id: Uuid, code: &str, message: impl Into<String>) -> Self {
        Self {
            id,
            ok: false,
            result: None,
            error: Some(ErrorPayload {
                code: code.to_string(),
                message: message.into(),
            }),
        }
    }
}

/// Error payload in a response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPayload {
    pub code: String,
    pub message: String,
}

// -- Method param/result types --

/// Known method names.
pub mod methods {
    pub const STORE_SECRET: &str = "store_secret";
    pub const REQUEST_LEASE: &str = "request_lease";
    pub const ACCESS_SECRET: &str = "access_secret";
    pub const REVOKE_LEASE: &str = "revoke_lease";
    pub const REVOKE_ALL_FOR_AGENT: &str = "revoke_all_for_agent";
    pub const LIST_SECRETS: &str = "list_secrets";
    pub const RENEW_LEASE: &str = "renew_lease";
    pub const DELETE_SECRET: &str = "delete_secret";
}

/// Params for `store_secret`.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoreSecretRequest {
    pub name: String,
    /// Base64-encoded plaintext (RFC 4648 §4, standard with padding).
    pub plaintext: String,
    pub kind: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl std::fmt::Debug for StoreSecretRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreSecretRequest")
            .field("name", &self.name)
            .field("plaintext", &"[REDACTED]")
            .field("kind", &self.kind)
            .field("description", &self.description)
            .finish()
    }
}

/// Params for `request_lease`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLeaseRequest {
    pub agent: String,
    pub secret_name: String,
    pub domain: String,
}

/// Params for `access_secret`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessSecretRequest {
    pub lease_id: Uuid,
    pub target_domain: String,
}

/// Result for `access_secret`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessSecretResponse {
    /// Base64-encoded decrypted secret.
    pub secret: String,
}

/// Params for `revoke_lease`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeLeaseRequest {
    pub lease_id: Uuid,
    pub reason: serde_json::Value,
}

/// Params for `revoke_all_for_agent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeAllForAgentRequest {
    pub agent: String,
}

/// Result for `revoke_all_for_agent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeAllForAgentResponse {
    pub revoked_count: usize,
}

/// Params for `list_secrets` (empty).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListSecretsRequest {}

/// Result for `list_secrets`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListSecretsResponse {
    pub secrets: Vec<serde_json::Value>,
}

/// Params for `renew_lease`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewLeaseRequest {
    pub lease_id: Uuid,
    pub extension_secs: i64,
}

/// Params for `delete_secret`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteSecretRequest {
    pub name: String,
}

// -- Error code mapping --

/// Map a vault `Error` to a protocol error code string.
pub fn error_to_code(err: &Error) -> &'static str {
    match err {
        Error::LeaseExpired(_) => "lease_expired",
        Error::LeaseRevoked(_) => "lease_revoked",
        Error::LeaseNotFound(_) => "lease_not_found",
        Error::AccessDenied { .. } => "access_denied",
        Error::NoPolicyForAgent(_) => "no_policy_for_agent",
        Error::SecretNotFound(_) => "secret_not_found",
        Error::SecretAlreadyExists(_) => "secret_already_exists",
        Error::EncryptionFailed => "encryption_failed",
        Error::DecryptionFailed => "decryption_failed",
        Error::KeySourceUnavailable(_) => "key_source_unavailable",
        Error::Storage(_) => "storage",
        Error::Transport(_) => "transport",
        Error::InvalidConfig(_) => "invalid_config",
        Error::NotSupported(_) => "not_supported",
        Error::Remote { .. } => "remote",
        Error::SessionNotFound => "session_not_found",
        Error::SessionExpired(_) => "session_expired",
        Error::SessionRevoked(_) => "session_revoked",
        Error::SessionLeaseLimitReached(_, _) => "session_lease_limit",
        Error::RenewalLimitReached(_, _) => "renewal_limit_reached",
    }
}

/// Build a full `ErrorPayload` from a vault `Error`.
pub fn error_to_payload(err: &Error) -> ErrorPayload {
    ErrorPayload {
        code: error_to_code(err).to_string(),
        message: err.to_string(),
    }
}

/// Protocol-level error code for malformed requests.
pub const CODE_INVALID_REQUEST: &str = "invalid_request";

/// Protocol-level error code for framing/encoding issues.
pub const CODE_PROTOCOL_ERROR: &str = "protocol_error";

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::*;
    use crate::error::Error;
    use crate::types::{AgentId, DomainScope, LeaseId, SecretName, SessionId};

    #[test]
    fn client_hello_serde_round_trip() {
        let hello = ClientHello::new();
        let json = serde_json::to_string(&hello).expect("should serialize ClientHello to json");
        let parsed: ClientHello = serde_json::from_str(&json).expect("should deserialize ClientHello from json");
        assert_eq!(parsed.protocol, PROTOCOL_NAME);
        assert_eq!(parsed.version, CURRENT_VERSION);
    }

    #[test]
    fn server_hello_accept_round_trip() {
        let hello = ServerHello::accept(1);
        let json = serde_json::to_string(&hello).expect("should serialize ServerHello accept to json");
        let parsed: ServerHello = serde_json::from_str(&json).expect("should deserialize ServerHello accept from json");
        assert!(parsed.ok);
        assert_eq!(parsed.version, 1);
        assert!(parsed.error.is_none());
    }

    #[test]
    fn server_hello_reject_round_trip() {
        let hello = ServerHello::reject("unsupported version 99");
        let json = serde_json::to_string(&hello).expect("should serialize ServerHello reject to json");
        let parsed: ServerHello = serde_json::from_str(&json).expect("should deserialize ServerHello reject from json");
        assert!(!parsed.ok);
        assert_eq!(parsed.version, CURRENT_VERSION);
        assert!(
            parsed
                .error
                .expect("should have error message in rejected hello")
                .contains("unsupported")
        );
    }

    #[test]
    fn wrong_protocol_name_detectable() {
        let json = r#"{"protocol": "not-zerolease", "version": 1}"#;
        let hello: ClientHello =
            serde_json::from_str(json).expect("should parse client hello with wrong protocol name");
        assert_ne!(hello.protocol, PROTOCOL_NAME);
    }

    #[test]
    fn unsupported_version_produces_rejection() {
        let client_version = 99u32;
        let response = if client_version > CURRENT_VERSION {
            ServerHello::reject(format!(
                "unsupported client version {client_version}; server supports {CURRENT_VERSION}"
            ))
        } else {
            ServerHello::accept(client_version)
        };
        assert!(!response.ok);
        assert!(
            response
                .error
                .as_ref()
                .expect("should have rejection error message")
                .contains("99")
        );
        assert_eq!(response.version, CURRENT_VERSION);
    }

    #[test]
    fn request_serde_round_trip() {
        let req = Request {
            id: Uuid::now_v7(),
            method: methods::REQUEST_LEASE.to_string(),
            params: serde_json::json!({
                "agent": "ci-agent-1",
                "secret_name": "github-pat",
                "domain": "api.github.com"
            }),
        };
        let json = serde_json::to_string(&req).expect("should serialize Request to json");
        let parsed: Request = serde_json::from_str(&json).expect("should deserialize Request from json");
        assert_eq!(parsed.id, req.id);
        assert_eq!(parsed.method, methods::REQUEST_LEASE);
    }

    #[test]
    fn success_response_round_trip() {
        let id = Uuid::now_v7();
        let resp = Response::success(id, serde_json::json!({"lease_id": "abc"}));
        let json = serde_json::to_string(&resp).expect("should serialize success Response to json");
        let parsed: Response = serde_json::from_str(&json).expect("should deserialize success Response from json");
        assert!(parsed.ok);
        assert_eq!(parsed.id, id);
        assert!(parsed.result.is_some());
        assert!(parsed.error.is_none());
    }

    #[test]
    fn error_response_round_trip() {
        let id = Uuid::now_v7();
        let err = Error::SecretNotFound(SecretName::new("missing"));
        let resp = Response::from_error(id, &err);
        let json = serde_json::to_string(&resp).expect("should serialize error Response to json");
        let parsed: Response = serde_json::from_str(&json).expect("should deserialize error Response from json");
        assert!(!parsed.ok);
        assert!(parsed.result.is_none());
        let payload = parsed.error.expect("should have error payload in error response");
        assert_eq!(payload.code, "secret_not_found");
        assert!(payload.message.contains("missing"));
    }

    #[test]
    fn protocol_error_response() {
        let id = Uuid::nil();
        let resp = Response::protocol_error(id, CODE_INVALID_REQUEST, "unknown method: foo");
        let json = serde_json::to_string(&resp).expect("should serialize protocol error Response to json");
        let parsed: Response =
            serde_json::from_str(&json).expect("should deserialize protocol error Response from json");
        assert!(!parsed.ok);
        let payload = parsed
            .error
            .expect("should have error payload in protocol error response");
        assert_eq!(payload.code, "invalid_request");
        assert!(payload.message.contains("foo"));
    }

    #[test]
    fn error_to_code_covers_all_variants() {
        let test_cases: Vec<Error> = vec![
            Error::LeaseExpired(LeaseId::new()),
            Error::LeaseRevoked(LeaseId::new()),
            Error::LeaseNotFound(LeaseId::new()),
            Error::AccessDenied {
                agent: AgentId::new("a"),
                secret: SecretName::new("s"),
                domain: DomainScope::new("d"),
            },
            Error::NoPolicyForAgent(AgentId::new("a")),
            Error::SecretNotFound(SecretName::new("s")),
            Error::SecretAlreadyExists(SecretName::new("s")),
            Error::EncryptionFailed,
            Error::DecryptionFailed,
            Error::KeySourceUnavailable("x".into()),
            Error::Storage("x".into()),
            Error::Transport("x".into()),
            Error::InvalidConfig("x".into()),
            Error::Remote {
                code: "x".into(),
                message: "x".into(),
            },
            Error::SessionNotFound,
            Error::SessionExpired(SessionId::new()),
            Error::SessionRevoked(SessionId::new()),
            Error::SessionLeaseLimitReached(SessionId::new(), 5),
            Error::RenewalLimitReached(LeaseId::new(), 3),
        ];

        let expected_codes = [
            "lease_expired", "lease_revoked", "lease_not_found", "access_denied", "no_policy_for_agent",
            "secret_not_found", "secret_already_exists", "encryption_failed", "decryption_failed",
            "key_source_unavailable", "storage", "transport", "invalid_config", "remote",
            "session_not_found", "session_expired", "session_revoked", "session_lease_limit",
            "renewal_limit_reached",
        ];

        for (err, expected) in test_cases.iter().zip(expected_codes.iter()) {
            assert_eq!(error_to_code(err), *expected, "wrong code for {err}");
        }
    }

    #[test]
    fn method_params_serde() {
        let params = RequestLeaseRequest {
            agent: "test-agent".into(),
            secret_name: "my-token".into(),
            domain: "api.example.com".into(),
        };
        let json = serde_json::to_string(&params).expect("should serialize RequestLeaseRequest to json");
        let parsed: RequestLeaseRequest =
            serde_json::from_str(&json).expect("should deserialize RequestLeaseRequest from json");
        assert_eq!(parsed.agent, "test-agent");
        assert_eq!(parsed.secret_name, "my-token");
        assert_eq!(parsed.domain, "api.example.com");
    }

    #[test]
    fn store_secret_params_with_base64() {
        let params = StoreSecretRequest {
            name: "my-key".into(),
            plaintext: base64::engine::general_purpose::STANDARD.encode(b"super-secret"),
            kind: serde_json::json!("ApiKey"),
            description: Some("test".into()),
        };
        let json = serde_json::to_string(&params).expect("should serialize StoreSecretRequest to json");
        let parsed: StoreSecretRequest =
            serde_json::from_str(&json).expect("should deserialize StoreSecretRequest from json");

        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&parsed.plaintext)
            .expect("should decode base64 plaintext");
        assert_eq!(decoded, b"super-secret");
    }

    #[test]
    fn unknown_method_detectable() {
        let req_json = r#"{"id": "00000000-0000-0000-0000-000000000000", "method": "nonexistent", "params": {}}"#;
        let req: Request = serde_json::from_str(req_json).expect("should deserialize request with unknown method");
        let known = [
            methods::STORE_SECRET,
            methods::REQUEST_LEASE,
            methods::ACCESS_SECRET,
            methods::REVOKE_LEASE,
            methods::REVOKE_ALL_FOR_AGENT,
            methods::LIST_SECRETS,
            methods::RENEW_LEASE,
            methods::DELETE_SECRET,
        ];
        assert!(!known.contains(&req.method.as_str()));
        let resp = Response::protocol_error(req.id, CODE_INVALID_REQUEST, format!("unknown method: {}", req.method));
        let payload = resp
            .error
            .expect("should have error payload for unknown method response");
        assert_eq!(payload.code, "invalid_request");
    }

    #[test]
    fn malformed_params_detectable() {
        let req_json =
            r#"{"id": "00000000-0000-0000-0000-000000000000", "method": "request_lease", "params": {"agent": 123}}"#;
        let req: Request = serde_json::from_str(req_json).expect("should deserialize request with malformed params");
        let result: Result<RequestLeaseRequest, _> = serde_json::from_value(req.params);
        assert!(result.is_err());
    }
}
