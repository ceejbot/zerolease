//! PostgreSQL secret store backend.

use chrono::{DateTime, Utc};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use zerolease::error::{Error, Result};
use zerolease::store::{
    BatchUpdateItem, CipherAlgorithm, SecretKind, SecretMetadata, SecretStore, StoreSecretParams,
    StoredSecret,
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
        let rows = sqlx::query(
            "SELECT id, name, kind, description, created_at, updated_at, version FROM secrets",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::Storage(format!("list query failed: {e}")))?;

        let mut result = Vec::with_capacity(rows.len());
        for row in &rows {
            let id_str: String = row.try_get("id").map_err(|e| Error::Storage(e.to_string()))?;
            let id_uuid =
                Uuid::parse_str(&id_str).map_err(|e| Error::Storage(e.to_string()))?;
            let name_str: String =
                row.try_get("name").map_err(|e| Error::Storage(e.to_string()))?;
            let kind_str: String =
                row.try_get("kind").map_err(|e| Error::Storage(e.to_string()))?;
            let description: Option<String> =
                row.try_get("description").map_err(|e| Error::Storage(e.to_string()))?;
            let created_at: DateTime<Utc> = row
                .try_get::<DateTime<Utc>, _>("created_at")
                .map_err(|e| Error::Storage(e.to_string()))?;
            let updated_at: DateTime<Utc> = row
                .try_get::<DateTime<Utc>, _>("updated_at")
                .map_err(|e| Error::Storage(e.to_string()))?;
            let version: i32 =
                row.try_get("version").map_err(|e| Error::Storage(e.to_string()))?;

            result.push(SecretMetadata {
                id: SecretId::from_uuid(id_uuid),
                name: SecretName::new(name_str),
                kind: SecretKind::parse_db(&kind_str)?,
                description,
                created_at,
                updated_at,
                version: version as u32,
            });
        }
        Ok(result)
    }
}


fn row_to_stored_secret(row: &sqlx::postgres::PgRow) -> Result<StoredSecret> {
    let id_str: String = row.try_get("id").map_err(|e| Error::Storage(e.to_string()))?;
    let id_uuid = Uuid::parse_str(&id_str).map_err(|e| Error::Storage(e.to_string()))?;
    let name_str: String = row.try_get("name").map_err(|e| Error::Storage(e.to_string()))?;
    let algorithm_str: String =
        row.try_get("algorithm").map_err(|e| Error::Storage(e.to_string()))?;
    let kind_str: String = row.try_get("kind").map_err(|e| Error::Storage(e.to_string()))?;
    let description: Option<String> =
        row.try_get("description").map_err(|e| Error::Storage(e.to_string()))?;
    let created_at: DateTime<Utc> = row
        .try_get::<DateTime<Utc>, _>("created_at")
        .map_err(|e| Error::Storage(e.to_string()))?;
    let updated_at: DateTime<Utc> = row
        .try_get::<DateTime<Utc>, _>("updated_at")
        .map_err(|e| Error::Storage(e.to_string()))?;
    let version: i32 = row.try_get("version").map_err(|e| Error::Storage(e.to_string()))?;
    let ciphertext: Vec<u8> =
        row.try_get("ciphertext").map_err(|e| Error::Storage(e.to_string()))?;
    let nonce: Vec<u8> = row.try_get("nonce").map_err(|e| Error::Storage(e.to_string()))?;

    Ok(StoredSecret {
        id: SecretId::from_uuid(id_uuid),
        name: SecretName::new(name_str),
        ciphertext,
        nonce,
        algorithm: CipherAlgorithm::parse_db(&algorithm_str)?,
        kind: SecretKind::parse_db(&kind_str)?,
        description,
        created_at,
        updated_at,
        version: version as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerolease::store::CipherAlgorithm;

    fn test_url() -> String {
        std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/zerolease_test".to_string())
    }

    async fn test_store() -> PostgresStore {
        let store = PostgresStore::new(&test_url())
            .await
            .expect("should create store");
        sqlx::query("DELETE FROM secrets")
            .execute(&store.pool)
            .await
            .expect("should clean test data");
        store
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

    #[tokio::test]
    #[ignore] // requires running PostgreSQL with zerolease_test database
    async fn put_and_get_round_trip() {
        let store = test_store().await;
        let stored = store.put(test_params("pg-secret")).await.expect("put");
        assert_eq!(stored.name, SecretName::new("pg-secret"));
        assert_eq!(stored.version, 1);
        let fetched = store.get(&SecretName::new("pg-secret")).await.expect("get");
        assert_eq!(fetched.ciphertext, stored.ciphertext);
    }

    #[tokio::test]
    #[ignore]
    async fn put_duplicate_name_errors() {
        let store = test_store().await;
        store.put(test_params("pg-dup")).await.expect("first put");
        let err = store.put(test_params("pg-dup")).await.expect_err("dup").to_string();
        assert!(err.contains("already exists"), "error was: {err}");
    }

    #[tokio::test]
    #[ignore]
    async fn get_missing_errors() {
        let store = test_store().await;
        let err = store.get(&SecretName::new("pg-nope")).await.expect_err("missing").to_string();
        assert!(err.contains("not found"), "error was: {err}");
    }

    #[tokio::test]
    #[ignore]
    async fn update_increments_version() {
        let store = test_store().await;
        store.put(test_params("pg-versioned")).await.expect("put");
        let updated = store
            .update(&SecretName::new("pg-versioned"), vec![10, 20], vec![1; 12], CipherAlgorithm::Aes256Gcm)
            .await
            .expect("update");
        assert_eq!(updated.version, 2);
    }

    #[tokio::test]
    #[ignore]
    async fn delete_removes_secret() {
        let store = test_store().await;
        store.put(test_params("pg-doomed")).await.expect("put");
        store.delete(&SecretName::new("pg-doomed")).await.expect("delete");
        assert!(store.get(&SecretName::new("pg-doomed")).await.is_err());
    }

    #[tokio::test]
    #[ignore]
    async fn list_returns_metadata() {
        let store = test_store().await;
        store.put(test_params("pg-first")).await.expect("put");
        store.put(test_params("pg-second")).await.expect("put");
        let list = store.list().await.expect("list");
        assert_eq!(list.len(), 2);
    }
}
