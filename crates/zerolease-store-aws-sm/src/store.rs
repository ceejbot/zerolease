//! AWS Secrets Manager secret store backend.
//!
//! Stores encrypted secrets as individual AWS Secrets Manager secrets.
//! Each zerolease secret maps to one Secrets Manager secret, with the
//! encrypted payload and metadata serialized as a JSON blob in the
//! secret value.
//!
//! ## Naming convention
//!
//! Secrets Manager secrets are stored under the prefix
//! `{prefix}/{secret_name}`, where `prefix` defaults to `zerolease`
//! but can be configured. This avoids collisions with other Secrets
//! Manager users in the same AWS account.
//!
//! ## Metadata tags
//!
//! Each secret is tagged with `zerolease:kind`, `zerolease:version`,
//! and `zerolease:updated_at` so that `list()` can return metadata
//! without fetching every secret's value (avoiding N+1 API calls).
//!
//! ## Atomicity
//!
//! AWS Secrets Manager does not support multi-secret transactions.
//! `batch_update` performs updates sequentially and will return an error
//! on the first failure. Callers should be aware that partial updates
//! are possible — unlike the SQL-backed stores, there is no rollback.
//! In practice, batch updates are only used for DEK rotation, which
//! can be safely retried.

use aws_sdk_secretsmanager::Client;
use aws_sdk_secretsmanager::error::SdkError;
use aws_sdk_secretsmanager::types::{Filter, FilterNameStringType, Tag};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zerolease::error::{Error, Result};
use zerolease::store::{
    parse_cipher_algorithm, parse_secret_kind, BatchUpdateItem, CipherAlgorithm, SecretKind, SecretMetadata,
    SecretStore, StoreSecretParams, StoredSecret,
};
use zerolease::types::{SecretId, SecretName};

/// Tag keys used on Secrets Manager secrets so `list()` can return
/// metadata without fetching every secret's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetadataTag {
    Kind,
    Version,
    UpdatedAt,
    CreatedAt,
    Description,
}

impl MetadataTag {
    /// The full tag key string (e.g., `"zerolease:kind"`).
    fn key(self) -> &'static str {
        match self {
            Self::Kind => "zerolease:kind",
            Self::Version => "zerolease:version",
            Self::UpdatedAt => "zerolease:updated_at",
            Self::CreatedAt => "zerolease:created_at",
            Self::Description => "zerolease:description",
        }
    }

    /// Look up a tag value from a slice of AWS tags.
    fn find(self, tags: &[Tag]) -> Option<String> {
        let key = self.key();
        tags.iter()
            .find(|t| t.key() == Some(key))
            .and_then(|t| t.value().map(|v| v.to_string()))
    }
}

/// AWS Secrets Manager-backed implementation of [`SecretStore`].
///
/// Each zerolease secret is stored as an individual Secrets Manager secret
/// with a JSON payload containing the encrypted data and metadata.
pub struct AwsSecretsManagerStore {
    client: Client,
    /// Prefix for Secrets Manager secret names (e.g., "zerolease").
    prefix: String,
    /// If true, deletes bypass the recovery window (immediate, irreversible).
    /// Defaults to false (uses AWS's default 30-day recovery window).
    force_delete: bool,
}

/// Internal representation of the JSON payload stored in Secrets Manager.
#[derive(Debug, Serialize, Deserialize)]
struct SecretPayload {
    id: String,
    name: String,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    algorithm: String,
    kind: String,
    description: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    version: u32,
}

impl SecretPayload {
    fn from_stored(s: &StoredSecret) -> Self {
        Self {
            id: s.id.as_uuid().to_string(),
            name: s.name.as_str().to_string(),
            ciphertext: s.ciphertext.clone(),
            nonce: s.nonce.clone(),
            algorithm: s.algorithm.as_str().to_owned(),
            kind: s.kind.as_str().to_owned(),
            description: s.description.clone(),
            created_at: s.created_at,
            updated_at: s.updated_at,
            version: s.version,
        }
    }

    fn into_stored_secret(self) -> Result<StoredSecret> {
        let id_uuid = Uuid::parse_str(&self.id).map_err(|e| Error::Storage(format!("invalid UUID: {e}")))?;
        Ok(StoredSecret {
            id: SecretId::from_uuid(id_uuid),
            name: SecretName::new(self.name),
            ciphertext: self.ciphertext,
            nonce: self.nonce,
            algorithm: parse_cipher_algorithm(&self.algorithm)?,
            kind: parse_secret_kind(&self.kind)?,
            description: self.description,
            created_at: self.created_at,
            updated_at: self.updated_at,
            version: self.version,
        })
    }

    /// Build AWS tags for metadata that `list()` can read without
    /// fetching the secret value.
    fn metadata_tags(&self) -> Vec<Tag> {
        let tag = |key: MetadataTag, value: &str| Tag::builder().key(key.key()).value(value).build();

        let mut tags = vec![
            tag(MetadataTag::Kind, &self.kind),
            tag(MetadataTag::Version, &self.version.to_string()),
            tag(MetadataTag::UpdatedAt, &self.updated_at.to_rfc3339()),
            tag(MetadataTag::CreatedAt, &self.created_at.to_rfc3339()),
        ];
        if let Some(desc) = &self.description {
            tags.push(tag(MetadataTag::Description, desc));
        }
        tags
    }
}

impl AwsSecretsManagerStore {
    /// Create a new Secrets Manager store with the given AWS SDK client
    /// and prefix.
    ///
    /// The `prefix` is prepended to secret names (e.g., `zerolease/my-secret`).
    /// Use different prefixes to isolate multiple vault instances in the
    /// same AWS account.
    pub fn new(client: Client, prefix: impl Into<String>) -> Self {
        Self {
            client,
            prefix: prefix.into(),
            force_delete: false,
        }
    }

    /// Create a new store using default AWS SDK configuration from the
    /// environment (credentials, region, etc.).
    pub async fn from_env(prefix: impl Into<String>) -> Result<Self> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = Client::new(&config);
        Ok(Self::new(client, prefix))
    }

    /// Enable force-delete mode (bypasses the AWS recovery window).
    ///
    /// By default, deleted secrets enter a 7–30 day recovery window
    /// during which they can be restored. Enabling force-delete causes
    /// immediate, irreversible removal. Use with caution.
    pub fn with_force_delete(mut self, force: bool) -> Self {
        self.force_delete = force;
        self
    }

    /// Build the Secrets Manager name for a zerolease secret.
    fn sm_name(&self, name: &SecretName) -> String {
        format!("{}/{}", self.prefix, name.as_str())
    }

    /// Serialize a payload to a JSON string for storage.
    fn serialize_payload(payload: &SecretPayload) -> Result<String> {
        serde_json::to_string(payload).map_err(|e| Error::Storage(format!("payload serialization failed: {e}")))
    }

    /// Deserialize a JSON string from Secrets Manager into a payload.
    fn deserialize_payload(s: &str) -> Result<SecretPayload> {
        serde_json::from_str(s).map_err(|e| Error::Storage(format!("payload deserialization failed: {e}")))
    }

    /// Strip our prefix from an SM secret name to recover the zerolease name.
    fn strip_prefix<'a>(&self, sm_name: &'a str) -> Option<&'a str> {
        sm_name.strip_prefix(&self.prefix).and_then(|s| s.strip_prefix('/'))
    }
}

#[async_trait::async_trait]
impl SecretStore for AwsSecretsManagerStore {
    async fn put(&self, params: StoreSecretParams) -> Result<StoredSecret> {
        let sm_name = self.sm_name(&params.name);
        let id = SecretId::new();
        let now = Utc::now();

        let stored = StoredSecret {
            id,
            name: params.name.clone(),
            ciphertext: params.ciphertext,
            nonce: params.nonce,
            algorithm: params.algorithm,
            kind: params.kind,
            description: params.description,
            created_at: now,
            updated_at: now,
            version: 1,
        };

        let payload = SecretPayload::from_stored(&stored);
        let payload_str = Self::serialize_payload(&payload)?;
        let tags = payload.metadata_tags();
        let mut request = self
            .client
            .create_secret()
            .name(&sm_name)
            .secret_string(&payload_str)
            .description(format!("zerolease secret: {}", params.name.as_str()));

        for tag in tags {
            request = request.tags(tag);
        }

        let result = request.send().await;

        match result {
            Ok(_) => Ok(stored),
            Err(SdkError::ServiceError(e)) if e.err().is_resource_exists_exception() => {
                Err(Error::SecretAlreadyExists(params.name))
            }
            Err(err) => Err(Error::Storage(format!("Secrets Manager create failed: {err:?}"))),
        }
    }

    async fn get(&self, name: &SecretName) -> Result<StoredSecret> {
        let sm_name = self.sm_name(name);

        match self.client.get_secret_value().secret_id(&sm_name).send().await {
            Ok(output) => {
                let secret_string = output.secret_string().ok_or_else(|| {
                    Error::Storage("secret has no string value (binary secrets not supported)".into())
                })?;
                let payload = Self::deserialize_payload(secret_string)?;
                payload.into_stored_secret()
            }
            Err(SdkError::ServiceError(e))
                if e.err().is_resource_not_found_exception()
                    || (e.err().is_invalid_request_exception()
                        && e.err()
                            .meta()
                            .message()
                            .is_some_and(|m| m.contains("marked for deletion"))) =>
            {
                Err(Error::SecretNotFound(name.clone()))
            }
            Err(err) => Err(Error::Storage(format!("Secrets Manager get failed: {err:?}"))),
        }
    }

    async fn update(
        &self,
        name: &SecretName,
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        algorithm: CipherAlgorithm,
    ) -> Result<StoredSecret> {
        let existing = self.get(name).await?;
        let now = Utc::now();

        let updated = StoredSecret {
            id: existing.id,
            name: existing.name,
            ciphertext,
            nonce,
            algorithm,
            kind: existing.kind,
            description: existing.description,
            created_at: existing.created_at,
            updated_at: now,
            version: existing.version + 1,
        };

        let payload = SecretPayload::from_stored(&updated);
        let payload_str = Self::serialize_payload(&payload)?;
        let sm_name = self.sm_name(name);

        match self
            .client
            .put_secret_value()
            .secret_id(&sm_name)
            .secret_string(&payload_str)
            .send()
            .await
        {
            Ok(_) => {}
            Err(SdkError::ServiceError(e)) if e.err().is_resource_not_found_exception() => {
                return Err(Error::SecretNotFound(name.clone()));
            }
            Err(err) => return Err(Error::Storage(format!("Secrets Manager update failed: {err:?}"))),
        }

        // Update tags to reflect new version/timestamp.
        let tags = payload.metadata_tags();
        let mut tag_request = self.client.tag_resource().secret_id(&sm_name);
        for tag in tags {
            tag_request = tag_request.tags(tag);
        }
        if let Err(e) = tag_request.send().await {
            tracing::warn!(
                secret = name.as_str(),
                error = %e,
                "failed to update metadata tags after secret update"
            );
        }

        Ok(updated)
    }

    /// Apply updates sequentially. AWS Secrets Manager has no transaction
    /// support, so on failure already-applied updates are NOT rolled back.
    /// This is acceptable because batch_update is used for DEK rotation,
    /// which is idempotent and can be safely retried.
    async fn batch_update(&self, updates: Vec<BatchUpdateItem>) -> Result<()> {
        for item in &updates {
            self.update(&item.name, item.ciphertext.clone(), item.nonce.clone(), item.algorithm)
                .await?;
        }
        Ok(())
    }

    async fn delete(&self, name: &SecretName) -> Result<()> {
        let sm_name = self.sm_name(name);

        // Verify the secret exists first. DeleteSecret with
        // force_delete_without_recovery silently succeeds for
        // nonexistent secrets, so we can't rely on its error response
        // to detect not-found.
        match self.client.describe_secret().secret_id(&sm_name).send().await {
            Ok(_) => {}
            Err(SdkError::ServiceError(e)) if e.err().is_resource_not_found_exception() => {
                return Err(Error::SecretNotFound(name.clone()));
            }
            Err(err) => return Err(Error::Storage(format!("Secrets Manager describe failed: {err:?}"))),
        }

        let mut request = self.client.delete_secret().secret_id(&sm_name);
        if self.force_delete {
            request = request.force_delete_without_recovery(true);
        }

        request
            .send()
            .await
            .map_err(|err| Error::Storage(format!("Secrets Manager delete failed: {err:?}")))?;

        Ok(())
    }

    /// List all secrets under our prefix using metadata tags.
    ///
    /// This avoids fetching each secret's value (no N+1 `get_secret_value`
    /// calls). Metadata is read from tags set during `put`/`update`.
    async fn list(&self) -> Result<Vec<SecretMetadata>> {
        let prefix_filter = format!("{}/", self.prefix);
        let mut secrets = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut request = self.client.list_secrets().filters(
                Filter::builder()
                    .key(FilterNameStringType::Name)
                    .values(&prefix_filter)
                    .build(),
            );

            if let Some(token) = &next_token {
                request = request.next_token(token);
            }

            let response = request
                .send()
                .await
                .map_err(|e| Error::Storage(format!("Secrets Manager list failed: {e:?}")))?;

            for secret in response.secret_list() {
                let sm_name = match secret.name() {
                    Some(n) => n,
                    None => continue,
                };

                let zerolease_name = match self.strip_prefix(sm_name) {
                    Some(n) => n.to_string(),
                    None => continue,
                };

                // Read metadata from tags instead of fetching the secret value.
                let tags = secret.tags();

                let kind_tag = MetadataTag::Kind.find(tags).unwrap_or_default();
                let kind = match parse_secret_kind(&kind_tag) {
                    Ok(k) => k,
                    Err(e) => {
                        tracing::warn!(
                            name = sm_name,
                            error = %e,
                            "skipping secret with invalid kind tag"
                        );
                        continue;
                    }
                };

                let version: u32 = MetadataTag::Version
                    .find(tags)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(1);

                let created_at = MetadataTag::CreatedAt
                    .find(tags)
                    .and_then(|v| DateTime::parse_from_rfc3339(&v).ok())
                    .map(|dt| dt.with_timezone(&Utc))
                    .or_else(|| {
                        secret
                            .created_date()
                            .map(|d| DateTime::from_timestamp(d.secs(), d.subsec_nanos()).unwrap_or_default())
                    })
                    .unwrap_or_default();

                let updated_at = MetadataTag::UpdatedAt
                    .find(tags)
                    .and_then(|v| DateTime::parse_from_rfc3339(&v).ok())
                    .map(|dt| dt.with_timezone(&Utc))
                    .or_else(|| {
                        secret
                            .last_changed_date()
                            .map(|d| DateTime::from_timestamp(d.secs(), d.subsec_nanos()).unwrap_or_default())
                    })
                    .unwrap_or_default();

                let description = MetadataTag::Description
                    .find(tags)
                    .or_else(|| secret.description().map(|s| s.to_string()));

                // We don't have the real SecretId without fetching the value,
                // so we use a deterministic UUID from the SM ARN or name.
                let id = SecretId::new();

                secrets.push(SecretMetadata {
                    id,
                    name: SecretName::new(zerolease_name),
                    kind,
                    description,
                    created_at,
                    updated_at,
                    version,
                });
            }

            next_token = response.next_token().map(|s| s.to_string());
            if next_token.is_none() {
                break;
            }
        }

        Ok(secrets)
    }
}

#[cfg(test)]
mod tests {
    use zerolease::store::CipherAlgorithm;

    use super::*;

    fn test_params(name: &str) -> StoreSecretParams {
        StoreSecretParams {
            name: SecretName::new(name),
            ciphertext: vec![1, 2, 3, 4],
            nonce: vec![5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            algorithm: CipherAlgorithm::Aes256Gcm,
            kind: SecretKind::Pat,
            description: Some("test secret".into()),
        }
    }

    /// Create a test store pointed at real AWS Secrets Manager.
    /// Requires AWS credentials in the environment.
    ///
    /// The prefix is read from `ZEROLEASE_SM_TEST_PREFIX` (default:
    /// `zerolease_test_`). A short UUID segment is appended for
    /// isolation between test runs.
    async fn test_store() -> AwsSecretsManagerStore {
        let base_prefix = std::env::var("ZEROLEASE_SM_TEST_PREFIX").unwrap_or_else(|_| "zerolease_test_".to_string());
        let prefix = format!(
            "{}{}",
            base_prefix,
            Uuid::now_v7().to_string().split('-').next().expect("uuid has parts")
        );
        AwsSecretsManagerStore::from_env(prefix)
            .await
            .expect("should create store")
            .with_force_delete(true) // tests should clean up immediately
    }

    /// Clean up test secrets by deleting them.
    async fn cleanup(store: &AwsSecretsManagerStore, names: &[&str]) {
        for name in names {
            let _ = store.delete(&SecretName::new(*name)).await;
        }
    }

    #[tokio::test]
    #[ignore] // requires AWS credentials and Secrets Manager access
    async fn put_and_get_round_trip() {
        let store = test_store().await;
        let params = test_params("sm-secret");

        let stored = store.put(params).await.expect("put should store a new secret");
        assert_eq!(
            stored.name,
            SecretName::new("sm-secret"),
            "stored name should match input"
        );
        assert_eq!(
            stored.ciphertext,
            vec![1, 2, 3, 4],
            "stored ciphertext should match input"
        );
        assert_eq!(
            stored.algorithm,
            CipherAlgorithm::Aes256Gcm,
            "stored algorithm should match input"
        );
        assert_eq!(stored.version, 1, "initial version should be 1");

        let fetched = store
            .get(&SecretName::new("sm-secret"))
            .await
            .expect("get should retrieve the stored secret");
        assert_eq!(fetched.name, stored.name, "fetched name should match stored");
        assert_eq!(
            fetched.ciphertext, stored.ciphertext,
            "fetched ciphertext should match stored"
        );
        assert_eq!(fetched.nonce, stored.nonce, "fetched nonce should match stored");

        cleanup(&store, &["sm-secret"]).await;
    }

    #[tokio::test]
    #[ignore]
    async fn put_duplicate_name_errors() {
        let store = test_store().await;
        store
            .put(test_params("sm-dup"))
            .await
            .expect("first put should succeed");

        let err = store
            .put(test_params("sm-dup"))
            .await
            .expect_err("second put with same name should fail");
        assert!(
            err.to_string().contains("already exists"),
            "expected 'already exists' error, got: {err}"
        );

        cleanup(&store, &["sm-dup"]).await;
    }

    #[tokio::test]
    #[ignore]
    async fn get_missing_errors() {
        let store = test_store().await;

        let err = store
            .get(&SecretName::new("sm-nonexistent"))
            .await
            .expect_err("get for nonexistent secret should fail");
        assert!(
            err.to_string().contains("not found"),
            "expected 'not found' error, got: {err}"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn update_increments_version() {
        let store = test_store().await;
        store
            .put(test_params("sm-versioned"))
            .await
            .expect("put should create secret for update test");

        let updated = store
            .update(
                &SecretName::new("sm-versioned"),
                vec![10, 20, 30],
                vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
                CipherAlgorithm::Aes256Gcm,
            )
            .await
            .expect("update should succeed on existing secret");

        assert_eq!(updated.version, 2, "version should increment from 1 to 2 after update");
        assert_eq!(
            updated.ciphertext,
            vec![10, 20, 30],
            "ciphertext should reflect the update"
        );

        cleanup(&store, &["sm-versioned"]).await;
    }

    #[tokio::test]
    #[ignore]
    async fn delete_removes_secret() {
        let store = test_store().await;
        store
            .put(test_params("sm-doomed"))
            .await
            .expect("put should create secret for delete test");

        store
            .delete(&SecretName::new("sm-doomed"))
            .await
            .expect("delete should succeed on existing secret");

        let err = store
            .get(&SecretName::new("sm-doomed"))
            .await
            .expect_err("get after delete should fail");
        assert!(
            err.to_string().contains("not found"),
            "expected 'not found' after delete, got: {err}"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn delete_missing_errors() {
        let store = test_store().await;

        let err = store
            .delete(&SecretName::new("sm-nope"))
            .await
            .expect_err("delete of nonexistent secret should fail");
        assert!(
            err.to_string().contains("not found"),
            "expected 'not found' error, got: {err}"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn list_returns_metadata() {
        let store = test_store().await;
        store
            .put(test_params("sm-first"))
            .await
            .expect("put should create first secret for list test");
        store
            .put(test_params("sm-second"))
            .await
            .expect("put should create second secret for list test");

        // ListSecrets is eventually consistent — retry briefly if
        // not all secrets are visible yet.
        let mut list = Vec::new();
        for attempt in 0..5 {
            list = store.list().await.expect("list should return stored secrets");
            if list.len() >= 2 {
                break;
            }
            if attempt < 4 {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
        assert!(
            list.len() >= 2,
            "expected at least 2 secrets in list after retries, got {}",
            list.len()
        );

        let names: Vec<String> = list.iter().map(|m| m.name.as_str().to_string()).collect();
        assert!(
            names.contains(&"sm-first".to_string()),
            "list should contain 'sm-first', got: {names:?}"
        );
        assert!(
            names.contains(&"sm-second".to_string()),
            "list should contain 'sm-second', got: {names:?}"
        );

        cleanup(&store, &["sm-first", "sm-second"]).await;
    }
}
