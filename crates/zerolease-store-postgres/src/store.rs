//! PostgreSQL secret store backend.

use chrono::{DateTime, Utc};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use zerolease::error::{Error, Result};
use zerolease::store::{
    BatchUpdateItem, CipherAlgorithm, SecretMetadata, SecretStore, StoreSecretParams, StoredSecret,
    parse_cipher_algorithm, parse_secret_kind,
};
use zerolease::types::{SecretId, SecretName};

/// PostgreSQL-backed implementation of [`SecretStore`].
///
/// All values are opaque encrypted blobs — this layer never sees plaintext.
pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    /// Connect to a PostgreSQL database at the given URL.
    ///
    /// Creates the secrets table if it does not already exist.
    pub async fn new(url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(url)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?;

        sqlx::query(include_str!("../../../sql/postgres_secrets.sql"))
            .execute(&pool)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?;

        Ok(Self { pool })
    }
}

#[async_trait::async_trait]
impl SecretStore for PostgresStore {
    async fn put(&self, params: StoreSecretParams) -> Result<StoredSecret> {
        let id = SecretId::new();
        let now = Utc::now();
        let id_str = id.as_uuid().to_string();
        let name_str = params.name.as_str().to_string();
        let algorithm_str = params.algorithm.as_str().to_owned();
        let kind_str = params.kind.as_str().to_owned();

        sqlx::query(
            "INSERT INTO secrets (id, name, ciphertext, nonce, algorithm, kind, description, created_at, updated_at, version)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 1)",
        )
        .bind(&id_str)
        .bind(&name_str)
        .bind(&params.ciphertext)
        .bind(&params.nonce)
        .bind(&algorithm_str)
        .bind(&kind_str)
        .bind(&params.description)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e
                && db_err.code().map(|c| c == "23505").unwrap_or(false)
            {
                return Error::SecretAlreadyExists(params.name.clone());
            }
            Error::Storage(format!("insert failed: {e}"))
        })?;

        Ok(StoredSecret {
            id,
            name: params.name,
            ciphertext: params.ciphertext,
            nonce: params.nonce,
            algorithm: params.algorithm,
            kind: params.kind,
            description: params.description,
            created_at: now,
            updated_at: now,
            version: 1,
        })
    }

    async fn get(&self, name: &SecretName) -> Result<StoredSecret> {
        let name_str = name.as_str().to_string();
        let row = sqlx::query(
            "SELECT id, name, ciphertext, nonce, algorithm, kind, description, created_at, updated_at, version
             FROM secrets WHERE name = $1",
        )
        .bind(&name_str)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Error::Storage(format!("query failed: {e}")))?
        .ok_or_else(|| Error::SecretNotFound(name.clone()))?;

        row_to_stored_secret(&row)
    }

    async fn update(
        &self,
        name: &SecretName,
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        algorithm: CipherAlgorithm,
    ) -> Result<StoredSecret> {
        let name_str = name.as_str().to_string();
        let now = Utc::now();
        let algorithm_str = algorithm.as_str().to_owned();

        let result = sqlx::query(
            "UPDATE secrets SET ciphertext = $1, nonce = $2, algorithm = $3, updated_at = $4, version = version + 1
             WHERE name = $5",
        )
        .bind(&ciphertext)
        .bind(&nonce)
        .bind(&algorithm_str)
        .bind(now)
        .bind(&name_str)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Storage(format!("update failed: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(Error::SecretNotFound(name.clone()));
        }

        self.get(name).await
    }

    async fn batch_update(&self, updates: Vec<BatchUpdateItem>) -> Result<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Error::Storage(format!("failed to begin transaction: {e}")))?;

        for item in &updates {
            let name_str = item.name.as_str().to_string();
            let now = Utc::now();
            let algorithm_str = item.algorithm.as_str().to_owned();

            let result = sqlx::query(
                "UPDATE secrets SET ciphertext = $1, nonce = $2, algorithm = $3, updated_at = $4, version = version + 1 WHERE name = $5",
            )
            .bind(&item.ciphertext)
            .bind(&item.nonce)
            .bind(&algorithm_str)
            .bind(now)
            .bind(&name_str)
            .execute(&mut *tx)
            .await
            .map_err(|e| Error::Storage(format!("batch update failed: {e}")))?;

            if result.rows_affected() == 0 {
                return Err(Error::SecretNotFound(item.name.clone()));
            }
        }

        tx.commit()
            .await
            .map_err(|e| Error::Storage(format!("transaction commit failed: {e}")))?;

        Ok(())
    }

    async fn delete(&self, name: &SecretName) -> Result<()> {
        let name_str = name.as_str().to_string();
        let result = sqlx::query("DELETE FROM secrets WHERE name = $1")
            .bind(&name_str)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Storage(format!("delete failed: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(Error::SecretNotFound(name.clone()));
        }
        Ok(())
    }

    async fn list(&self) -> Result<Vec<SecretMetadata>> {
        let rows = sqlx::query("SELECT id, name, kind, description, created_at, updated_at, version FROM secrets")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Error::Storage(format!("list query failed: {e}")))?;

        rows.iter().map(row_to_metadata).collect()
    }
}

/// Extract a column value from a PostgreSQL row, mapping errors to `Error::Storage`.
macro_rules! col {
    ($row:expr, $name:expr, $type:ty) => {
        $row.try_get::<$type, _>($name)
            .map_err(|e| Error::Storage(e.to_string()))?
    };
}

/// Parse a UUID string column into a `SecretId`.
fn parse_id(row: &sqlx::postgres::PgRow) -> Result<SecretId> {
    let id_str: String = col!(row, "id", String);
    let uuid = Uuid::parse_str(&id_str).map_err(|e| Error::Storage(e.to_string()))?;
    Ok(SecretId::from_uuid(uuid))
}

fn row_to_stored_secret(row: &sqlx::postgres::PgRow) -> Result<StoredSecret> {
    Ok(StoredSecret {
        id: parse_id(row)?,
        name: SecretName::new(col!(row, "name", String)),
        ciphertext: col!(row, "ciphertext", Vec<u8>),
        nonce: col!(row, "nonce", Vec<u8>),
        algorithm: parse_cipher_algorithm(&col!(row, "algorithm", String))?,
        kind: parse_secret_kind(&col!(row, "kind", String))?,
        description: col!(row, "description", Option<String>),
        created_at: col!(row, "created_at", DateTime<Utc>),
        updated_at: col!(row, "updated_at", DateTime<Utc>),
        version: col!(row, "version", i32) as u32,
    })
}

fn row_to_metadata(row: &sqlx::postgres::PgRow) -> Result<SecretMetadata> {
    Ok(SecretMetadata {
        id: parse_id(row)?,
        name: SecretName::new(col!(row, "name", String)),
        kind: parse_secret_kind(&col!(row, "kind", String))?,
        description: col!(row, "description", Option<String>),
        created_at: col!(row, "created_at", DateTime<Utc>),
        updated_at: col!(row, "updated_at", DateTime<Utc>),
        version: col!(row, "version", i32) as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerolease::store::CipherAlgorithm;

    fn test_url() -> String {
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://localhost/zerolease_test".to_string())
    }

    async fn test_store() -> PostgresStore {
        PostgresStore::new(&test_url()).await.expect("should create store")
    }

    fn test_params(name: &str) -> StoreSecretParams {
        StoreSecretParams {
            name: SecretName::new(name),
            ciphertext: vec![1, 2, 3, 4],
            nonce: vec![5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            algorithm: CipherAlgorithm::Aes256Gcm,
            kind: zerolease::store::SecretKind::Pat,
            description: Some("test secret".into()),
        }
    }

    /// Clean up specific secrets by name (each test cleans up after itself).
    async fn cleanup(store: &PostgresStore, names: &[&str]) {
        for name in names {
            let _ = store.delete(&SecretName::new(*name)).await;
        }
    }

    #[tokio::test]
    #[ignore] // requires running PostgreSQL with zerolease_test database
    async fn put_and_get_round_trip() {
        let store = test_store().await;
        cleanup(&store, &["pg-roundtrip"]).await;

        let stored = store
            .put(test_params("pg-roundtrip"))
            .await
            .expect("put should store secret");
        assert_eq!(stored.name, SecretName::new("pg-roundtrip"), "name should match");
        assert_eq!(stored.version, 1, "initial version should be 1");

        let fetched = store
            .get(&SecretName::new("pg-roundtrip"))
            .await
            .expect("get should retrieve secret");
        assert_eq!(fetched.ciphertext, stored.ciphertext, "ciphertext should match");

        cleanup(&store, &["pg-roundtrip"]).await;
    }

    #[tokio::test]
    #[ignore]
    async fn put_duplicate_name_errors() {
        let store = test_store().await;
        cleanup(&store, &["pg-dup"]).await;

        store
            .put(test_params("pg-dup"))
            .await
            .expect("first put should succeed");
        let err = store
            .put(test_params("pg-dup"))
            .await
            .expect_err("duplicate put should fail")
            .to_string();
        assert!(err.contains("already exists"), "expected 'already exists', got: {err}");

        cleanup(&store, &["pg-dup"]).await;
    }

    #[tokio::test]
    #[ignore]
    async fn get_missing_errors() {
        let store = test_store().await;

        let err = store
            .get(&SecretName::new("pg-nonexistent"))
            .await
            .expect_err("get for missing secret should fail")
            .to_string();
        assert!(err.contains("not found"), "expected 'not found', got: {err}");
    }

    #[tokio::test]
    #[ignore]
    async fn update_increments_version() {
        let store = test_store().await;
        cleanup(&store, &["pg-versioned"]).await;

        store
            .put(test_params("pg-versioned"))
            .await
            .expect("put should create secret");
        let updated = store
            .update(
                &SecretName::new("pg-versioned"),
                vec![10, 20],
                vec![1; 12],
                CipherAlgorithm::Aes256Gcm,
            )
            .await
            .expect("update should succeed");
        assert_eq!(updated.version, 2, "version should increment to 2");

        cleanup(&store, &["pg-versioned"]).await;
    }

    #[tokio::test]
    #[ignore]
    async fn delete_removes_secret() {
        let store = test_store().await;
        cleanup(&store, &["pg-doomed"]).await;

        store
            .put(test_params("pg-doomed"))
            .await
            .expect("put should create secret");
        store
            .delete(&SecretName::new("pg-doomed"))
            .await
            .expect("delete should succeed");

        let err = store
            .get(&SecretName::new("pg-doomed"))
            .await
            .expect_err("get after delete should fail");
        assert!(
            err.to_string().contains("not found"),
            "expected 'not found' after delete"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn list_returns_metadata() {
        let store = test_store().await;
        cleanup(&store, &["pg-list-a", "pg-list-b"]).await;

        store.put(test_params("pg-list-a")).await.expect("put first");
        store.put(test_params("pg-list-b")).await.expect("put second");

        let list = store.list().await.expect("list should succeed");
        let names: Vec<String> = list.iter().map(|m| m.name.as_str().to_string()).collect();
        assert!(
            names.contains(&"pg-list-a".to_string()),
            "list should contain pg-list-a, got: {names:?}"
        );
        assert!(
            names.contains(&"pg-list-b".to_string()),
            "list should contain pg-list-b, got: {names:?}"
        );

        cleanup(&store, &["pg-list-a", "pg-list-b"]).await;
    }
}
