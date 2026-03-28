//! SQLite secret store backend using `rusqlite`.

use std::path::Path;
use std::sync::Arc;

use chrono::Utc;
use rusqlite::Connection;
use tokio::sync::Mutex;
use uuid::Uuid;
use zerolease::error::{Error, Result};
use zerolease::store::{
    BatchUpdateItem, CipherAlgorithm, SecretKind, SecretMetadata, SecretStore, StoreSecretParams, StoredSecret,
};
use zerolease::types::{SecretId, SecretName};

/// SQLite-backed implementation of [`SecretStore`] using `rusqlite`.
///
/// Functionally identical to the `sqlx`-based `SqliteStore` but uses
/// `rusqlite` to share `libsqlite3-sys` with downstream crates.
/// Blocking calls are run via `tokio::task::spawn_blocking`.
pub struct RusqliteStore {
    conn: Arc<Mutex<Connection>>,
}

impl RusqliteStore {
    /// Open (or create) a SQLite store at the given path.
    ///
    /// Creates the database file and schema if they do not already exist.
    pub async fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let conn = tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&path).map_err(|e| Error::Storage(format!("failed to open database: {e}")))?;
            conn.execute_batch(include_str!("../../../sql/sqlite_secrets.sql"))
                .map_err(|e| Error::Storage(format!("failed to create schema: {e}")))?;
            Ok::<_, Error>(conn)
        })
        .await
        .map_err(|e| Error::Storage(format!("spawn_blocking failed: {e}")))??;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }
}

#[async_trait::async_trait]
impl SecretStore for RusqliteStore {
    async fn put(&self, params: StoreSecretParams) -> Result<StoredSecret> {
        let id = SecretId::new();
        let now = Utc::now();
        let conn = Arc::clone(&self.conn);

        let id_str = id.as_uuid().to_string();
        let name_str = params.name.as_str().to_string();
        let algorithm_str = params.algorithm.as_str().to_owned();
        let kind_str = params.kind.as_str().to_owned();
        let now_str = now.to_rfc3339();
        let ciphertext = params.ciphertext.clone();
        let nonce = params.nonce.clone();
        let description = params.description.clone();
        let name_for_err = params.name.clone();

        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            conn.execute(
                "INSERT INTO secrets (id, name, ciphertext, nonce, algorithm, kind, description, created_at, updated_at, version)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1)",
                rusqlite::params![
                    id_str, name_str, ciphertext, nonce, algorithm_str, kind_str,
                    description, now_str, now_str,
                ],
            )
            .map_err(|e| {
                if let rusqlite::Error::SqliteFailure(ref err, _) = e && err.code == rusqlite::ErrorCode::ConstraintViolation {
                        return Error::SecretAlreadyExists(name_for_err);
                }
                Error::Storage(format!("insert failed: {e}"))
            })
        })
        .await
        .map_err(|e| Error::Storage(format!("spawn_blocking failed: {e}")))??;

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
        let conn = Arc::clone(&self.conn);
        let name_str = name.as_str().to_string();
        let name_clone = name.clone();

        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            let mut stmt = conn
                .prepare(
                    "SELECT id, name, ciphertext, nonce, algorithm, kind, description, created_at, updated_at, version
                     FROM secrets WHERE name = ?1",
                )
                .map_err(|e| Error::Storage(format!("prepare failed: {e}")))?;

            stmt.query_row(rusqlite::params![name_str], |row| {
                row_to_stored_secret(row)
                    .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))
            })
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Error::SecretNotFound(name_clone),
                _ => Error::Storage(format!("query failed: {e}")),
            })
        })
        .await
        .map_err(|e| Error::Storage(format!("spawn_blocking failed: {e}")))?
    }

    async fn update(
        &self,
        name: &SecretName,
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        algorithm: CipherAlgorithm,
    ) -> Result<StoredSecret> {
        let conn = Arc::clone(&self.conn);
        let name_str = name.as_str().to_string();
        let now_str = Utc::now().to_rfc3339();
        let algorithm_str = algorithm.as_str().to_owned();
        let name_clone = name.clone();

        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            let rows = conn
                .execute(
                    "UPDATE secrets SET ciphertext = ?1, nonce = ?2, algorithm = ?3, updated_at = ?4, version = version + 1
                     WHERE name = ?5",
                    rusqlite::params![ciphertext, nonce, algorithm_str, now_str, name_str],
                )
                .map_err(|e| Error::Storage(format!("update failed: {e}")))?;

            if rows == 0 {
                return Err(Error::SecretNotFound(name_clone.clone()));
            }

            // Re-fetch in the same blocking context to avoid a second mutex acquisition.
            let mut stmt = conn
                .prepare(
                    "SELECT id, name, ciphertext, nonce, algorithm, kind, description, created_at, updated_at, version
                     FROM secrets WHERE name = ?1",
                )
                .map_err(|e| Error::Storage(format!("prepare failed: {e}")))?;

            stmt.query_row(rusqlite::params![name_clone.as_str()], |row| {
                row_to_stored_secret(row)
                    .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))
            })
            .map_err(|e| Error::Storage(format!("query failed: {e}")))
        })
        .await
        .map_err(|e| Error::Storage(format!("spawn_blocking failed: {e}")))?
    }

    async fn batch_update(&self, updates: Vec<BatchUpdateItem>) -> Result<()> {
        let conn = Arc::clone(&self.conn);

        tokio::task::spawn_blocking(move || {
            let mut conn = conn.blocking_lock();
            let tx = conn
                .transaction()
                .map_err(|e| Error::Storage(format!("failed to begin transaction: {e}")))?;

            for item in &updates {
                let name_str = item.name.as_str().to_string();
                let now_str = Utc::now().to_rfc3339();
                let algorithm_str = item.algorithm.as_str().to_owned();

                let rows = tx
                    .execute(
                        "UPDATE secrets SET ciphertext = ?1, nonce = ?2, algorithm = ?3, updated_at = ?4, version = version + 1
                         WHERE name = ?5",
                        rusqlite::params![item.ciphertext, item.nonce, algorithm_str, now_str, name_str],
                    )
                    .map_err(|e| Error::Storage(format!("batch update failed: {e}")))?;

                if rows == 0 {
                    return Err(Error::SecretNotFound(item.name.clone()));
                }
            }

            tx.commit()
                .map_err(|e| Error::Storage(format!("transaction commit failed: {e}")))?;
            Ok(())
        })
        .await
        .map_err(|e| Error::Storage(format!("spawn_blocking failed: {e}")))?
    }

    async fn delete(&self, name: &SecretName) -> Result<()> {
        let conn = Arc::clone(&self.conn);
        let name_str = name.as_str().to_string();
        let name_clone = name.clone();

        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            let rows = conn
                .execute("DELETE FROM secrets WHERE name = ?1", rusqlite::params![name_str])
                .map_err(|e| Error::Storage(format!("delete failed: {e}")))?;

            if rows == 0 {
                return Err(Error::SecretNotFound(name_clone));
            }
            Ok(())
        })
        .await
        .map_err(|e| Error::Storage(format!("spawn_blocking failed: {e}")))?
    }

    async fn list(&self) -> Result<Vec<SecretMetadata>> {
        let conn = Arc::clone(&self.conn);

        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            let mut stmt = conn
                .prepare("SELECT id, name, kind, description, created_at, updated_at, version FROM secrets")
                .map_err(|e| Error::Storage(format!("prepare failed: {e}")))?;

            let rows = stmt
                .query_map([], |row| {
                    row_to_metadata(row).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
                    })
                })
                .map_err(|e| Error::Storage(format!("list query failed: {e}")))?;

            let mut result = Vec::new();
            for row in rows {
                result.push(row.map_err(|e| Error::Storage(format!("row extraction failed: {e}")))?);
            }
            Ok(result)
        })
        .await
        .map_err(|e| Error::Storage(format!("spawn_blocking failed: {e}")))?
    }
}

fn row_to_stored_secret(row: &rusqlite::Row<'_>) -> Result<StoredSecret> {
    let id_str: String = row.get("id").map_err(|e| Error::Storage(e.to_string()))?;
    let id_uuid = Uuid::parse_str(&id_str).map_err(|e| Error::Storage(e.to_string()))?;
    let name_str: String = row.get("name").map_err(|e| Error::Storage(e.to_string()))?;
    let algorithm_str: String = row.get("algorithm").map_err(|e| Error::Storage(e.to_string()))?;
    let kind_str: String = row.get("kind").map_err(|e| Error::Storage(e.to_string()))?;
    let description: Option<String> = row.get("description").map_err(|e| Error::Storage(e.to_string()))?;
    let created_at_str: String = row.get("created_at").map_err(|e| Error::Storage(e.to_string()))?;
    let updated_at_str: String = row.get("updated_at").map_err(|e| Error::Storage(e.to_string()))?;
    let version: i32 = row.get("version").map_err(|e| Error::Storage(e.to_string()))?;
    let ciphertext: Vec<u8> = row.get("ciphertext").map_err(|e| Error::Storage(e.to_string()))?;
    let nonce: Vec<u8> = row.get("nonce").map_err(|e| Error::Storage(e.to_string()))?;

    Ok(StoredSecret {
        id: SecretId::from_uuid(id_uuid),
        name: SecretName::new(name_str),
        ciphertext,
        nonce,
        algorithm: CipherAlgorithm::parse_db(&algorithm_str)?,
        kind: SecretKind::parse_db(&kind_str)?,
        description,
        created_at: chrono::DateTime::parse_from_rfc3339(&created_at_str)
            .map_err(|e| Error::Storage(format!("invalid created_at: {e}")))?
            .with_timezone(&Utc),
        updated_at: chrono::DateTime::parse_from_rfc3339(&updated_at_str)
            .map_err(|e| Error::Storage(format!("invalid updated_at: {e}")))?
            .with_timezone(&Utc),
        version: version as u32,
    })
}

fn row_to_metadata(row: &rusqlite::Row<'_>) -> Result<SecretMetadata> {
    let id_str: String = row.get("id").map_err(|e| Error::Storage(e.to_string()))?;
    let id_uuid = Uuid::parse_str(&id_str).map_err(|e| Error::Storage(e.to_string()))?;
    let name_str: String = row.get("name").map_err(|e| Error::Storage(e.to_string()))?;
    let kind_str: String = row.get("kind").map_err(|e| Error::Storage(e.to_string()))?;
    let description: Option<String> = row.get("description").map_err(|e| Error::Storage(e.to_string()))?;
    let created_at_str: String = row.get("created_at").map_err(|e| Error::Storage(e.to_string()))?;
    let updated_at_str: String = row.get("updated_at").map_err(|e| Error::Storage(e.to_string()))?;
    let version: i32 = row.get("version").map_err(|e| Error::Storage(e.to_string()))?;

    Ok(SecretMetadata {
        id: SecretId::from_uuid(id_uuid),
        name: SecretName::new(name_str),
        kind: SecretKind::parse_db(&kind_str)?,
        description,
        created_at: chrono::DateTime::parse_from_rfc3339(&created_at_str)
            .map_err(|e| Error::Storage(format!("invalid created_at: {e}")))?
            .with_timezone(&Utc),
        updated_at: chrono::DateTime::parse_from_rfc3339(&updated_at_str)
            .map_err(|e| Error::Storage(format!("invalid updated_at: {e}")))?
            .with_timezone(&Utc),
        version: version as u32,
    })
}

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;
    use zerolease::store::CipherAlgorithm;

    use super::*;

    async fn test_store() -> (RusqliteStore, NamedTempFile) {
        let tmp = NamedTempFile::new().expect("should create temp file");
        let store = RusqliteStore::new(tmp.path()).await.expect("should create store");
        (store, tmp)
    }

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

    #[tokio::test]
    async fn put_and_get_round_trip() {
        let (store, _tmp) = test_store().await;
        let params = test_params("my-secret");
        let stored = store.put(params).await.expect("should put secret");
        assert_eq!(stored.name, SecretName::new("my-secret"));
        assert_eq!(stored.ciphertext, vec![1, 2, 3, 4]);
        assert_eq!(stored.version, 1);
        let fetched = store
            .get(&SecretName::new("my-secret"))
            .await
            .expect("should get secret");
        assert_eq!(fetched.name, stored.name);
        assert_eq!(fetched.ciphertext, stored.ciphertext);
    }

    #[tokio::test]
    async fn put_duplicate_name_errors() {
        let (store, _tmp) = test_store().await;
        store.put(test_params("dup")).await.expect("first put");
        let err = store
            .put(test_params("dup"))
            .await
            .expect_err("duplicate put")
            .to_string();
        assert!(err.contains("already exists"), "error was: {err}");
    }

    #[tokio::test]
    async fn get_missing_errors() {
        let (store, _tmp) = test_store().await;
        let err = store
            .get(&SecretName::new("nope"))
            .await
            .expect_err("missing get")
            .to_string();
        assert!(err.contains("not found"), "error was: {err}");
    }

    #[tokio::test]
    async fn update_increments_version() {
        let (store, _tmp) = test_store().await;
        store.put(test_params("versioned")).await.expect("put");
        let updated = store
            .update(
                &SecretName::new("versioned"),
                vec![10, 20],
                vec![1; 12],
                CipherAlgorithm::Aes256Gcm,
            )
            .await
            .expect("update");
        assert_eq!(updated.version, 2);
        assert_eq!(updated.ciphertext, vec![10, 20]);
    }

    #[tokio::test]
    async fn delete_removes_secret() {
        let (store, _tmp) = test_store().await;
        store.put(test_params("doomed")).await.expect("put");
        store.delete(&SecretName::new("doomed")).await.expect("delete");
        assert!(store.get(&SecretName::new("doomed")).await.is_err());
    }

    #[tokio::test]
    async fn list_returns_metadata() {
        let (store, _tmp) = test_store().await;
        store.put(test_params("first")).await.expect("put first");
        store.put(test_params("second")).await.expect("put second");
        let list = store.list().await.expect("list");
        assert_eq!(list.len(), 2);
    }
}
