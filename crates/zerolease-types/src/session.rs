//! Session identity types.
//!
//! Sessions bind credential access to a trust context — typically a
//! user-initiated conversation or work unit. These types live in the
//! lightweight types crate so the provider crate can reference them
//! in `CredentialRequest` without depending on the full vault.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Unique identifier for a session.
///
/// Time-ordered (UUID v7) for audit log correlation. Appears in
/// audit events and lease parentage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(Uuid);

impl SessionId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "session:{}", self.0)
    }
}

/// Opaque token that maps to a session via `HashMap` lookup.
///
/// 128-bit random value. The vault generates the random bytes and
/// constructs the token via `from_bytes()`.
///
/// Security properties:
/// - Zeroized on drop (memory scrubbed)
/// - Debug output is redacted
/// - NOT Serialize — this is an in-process secret that must never be
///   persisted or sent over a wire
/// - In embedded mode, the token never leaves the process
#[derive(Clone, Eq, PartialEq, Hash, Zeroize, ZeroizeOnDrop)]
pub struct SessionToken([u8; 16]);

impl SessionToken {
    /// Construct a token from raw bytes. The vault is responsible for
    /// generating random bytes via `OsRng`.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionToken(***)")
    }
}

impl fmt::Display for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionToken(***)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_display_is_prefixed() {
        let id = SessionId::new();
        let s = id.to_string();
        assert!(s.starts_with("session:"));
    }

    #[test]
    fn session_token_debug_is_redacted() {
        let token = SessionToken::from_bytes([1; 16]);
        let debug = format!("{token:?}");
        assert_eq!(debug, "SessionToken(***)");
        assert!(!debug.contains("1"));
    }

    #[test]
    fn session_token_equality() {
        let a = SessionToken::from_bytes([1; 16]);
        let b = SessionToken::from_bytes([1; 16]);
        let c = SessionToken::from_bytes([2; 16]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn session_token_is_hashable() {
        use std::collections::HashMap;
        let mut map = HashMap::new();
        let token = SessionToken::from_bytes([42; 16]);
        map.insert(token.clone(), "test");
        assert_eq!(map.get(&token), Some(&"test"));
    }
}
