use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use serde::Serialize;
use sqlx::{Row, SqlitePool, sqlite::SqlitePoolOptions};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::config::Config;

#[derive(Clone)]
pub struct Store {
    pool: SqlitePool,
    blob_base_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct EventMetadata {
    pub cursor: i64,
    pub app_id: String,
    pub root_id: String,
    pub device_id: String,
    pub event_id: String,
    pub created_at_ms: i64,
    pub size: i64,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("event already exists")]
    Conflict,
    #[error("event not found")]
    NotFound,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
}

impl Store {
    pub async fn open(config: &Config) -> Result<Self, StoreError> {
        tokio::fs::create_dir_all(&config.blob_base_dir).await?;

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(config.database_options.clone())
            .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS events (
                cursor INTEGER PRIMARY KEY AUTOINCREMENT,
                app_id TEXT NOT NULL,
                root_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                size INTEGER NOT NULL,
                UNIQUE(app_id, root_id, device_id, event_id)
            )
            "#,
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_events_root_cursor
            ON events(app_id, root_id, cursor)
            "#,
        )
        .execute(&pool)
        .await?;

        Ok(Self {
            pool,
            blob_base_dir: config.blob_base_dir.clone(),
        })
    }

    /// Stores an event as ciphertext plus a metadata row.
    ///
    /// The two stores are committed in an order that keeps every interruption
    /// recoverable: the blob is staged under a temporary name, published by an
    /// atomic rename, and only then is the metadata transaction committed. A
    /// crash before that commit leaves an unreferenced blob that the next
    /// attempt with the same event ID overwrites, so a retry succeeds instead
    /// of being permanently rejected as a duplicate.
    pub async fn put_event(
        &self,
        app_id: &str,
        root_id: &str,
        device_id: &str,
        event_id: &str,
        body: Bytes,
    ) -> Result<EventMetadata, StoreError> {
        let path = self.blob_path(app_id, root_id, device_id, event_id);
        let parent = path.parent().expect("blob path always has a parent");
        tokio::fs::create_dir_all(parent).await?;

        // Staged outside the metadata transaction so the write lock below only
        // covers fast operations, whatever the size of the body.
        let staged_path = parent.join(format!("{event_id}.{}.tmp", Uuid::new_v4()));
        let staged = write_staged_blob(&staged_path, &body).await;

        let result = match staged {
            Ok(()) => {
                self.commit_event(
                    &staged_path,
                    &path,
                    app_id,
                    root_id,
                    device_id,
                    event_id,
                    body.len() as i64,
                )
                .await
            }
            Err(err) => Err(err),
        };

        if result.is_err() {
            let _ = tokio::fs::remove_file(&staged_path).await;
        }

        result
    }

    #[allow(clippy::too_many_arguments)]
    async fn commit_event(
        &self,
        staged_path: &Path,
        path: &Path,
        app_id: &str,
        root_id: &str,
        device_id: &str,
        event_id: &str,
        size: i64,
    ) -> Result<EventMetadata, StoreError> {
        let created_at_ms = now_ms();
        let mut tx = self.pool.begin().await?;

        // Taking the row first makes SQLite's writer lock serialize concurrent
        // uploads of the same event ID, so only one of them reaches the rename.
        let result = sqlx::query(
            r#"
            INSERT INTO events(app_id, root_id, device_id, event_id, created_at_ms, size)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(app_id)
        .bind(root_id)
        .bind(device_id)
        .bind(event_id)
        .bind(created_at_ms)
        .bind(size)
        .execute(&mut *tx)
        .await;

        let result = match result {
            Ok(result) => result,
            Err(err) if is_unique_violation(&err) => return Err(StoreError::Conflict),
            Err(err) => return Err(StoreError::Sql(err)),
        };

        tokio::fs::rename(staged_path, path).await?;
        sync_parent_dir(path).await?;

        tx.commit().await?;

        Ok(EventMetadata {
            cursor: result.last_insert_rowid(),
            app_id: app_id.to_owned(),
            root_id: root_id.to_owned(),
            device_id: device_id.to_owned(),
            event_id: event_id.to_owned(),
            created_at_ms,
            size,
        })
    }

    pub async fn get_event(
        &self,
        app_id: &str,
        root_id: &str,
        device_id: &str,
        event_id: &str,
    ) -> Result<Bytes, StoreError> {
        // The metadata row is what makes an event exist. A blob without one is
        // an upload that never committed, and serving it would contradict the
        // event feed, which does not list it.
        let committed: Option<i64> = sqlx::query_scalar(
            r#"
            SELECT cursor FROM events
            WHERE app_id = ? AND root_id = ? AND device_id = ? AND event_id = ?
            "#,
        )
        .bind(app_id)
        .bind(root_id)
        .bind(device_id)
        .bind(event_id)
        .fetch_optional(&self.pool)
        .await?;

        if committed.is_none() {
            return Err(StoreError::NotFound);
        }

        let path = self.blob_path(app_id, root_id, device_id, event_id);
        match tokio::fs::read(path).await {
            Ok(bytes) => Ok(Bytes::from(bytes)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Err(StoreError::NotFound),
            Err(err) => Err(StoreError::Io(err)),
        }
    }

    pub async fn list_events(
        &self,
        app_id: &str,
        root_id: &str,
        after: i64,
        limit: i64,
        device_id: Option<&str>,
    ) -> Result<Vec<EventMetadata>, StoreError> {
        let rows = if let Some(device_id) = device_id {
            sqlx::query(
                r#"
                SELECT cursor, app_id, root_id, device_id, event_id, created_at_ms, size
                FROM events
                WHERE app_id = ? AND root_id = ? AND cursor > ? AND device_id = ?
                ORDER BY cursor ASC
                LIMIT ?
                "#,
            )
            .bind(app_id)
            .bind(root_id)
            .bind(after)
            .bind(device_id)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                r#"
                SELECT cursor, app_id, root_id, device_id, event_id, created_at_ms, size
                FROM events
                WHERE app_id = ? AND root_id = ? AND cursor > ?
                ORDER BY cursor ASC
                LIMIT ?
                "#,
            )
            .bind(app_id)
            .bind(root_id)
            .bind(after)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        };

        rows.into_iter()
            .map(|row| {
                Ok(EventMetadata {
                    cursor: row.try_get("cursor")?,
                    app_id: row.try_get("app_id")?,
                    root_id: row.try_get("root_id")?,
                    device_id: row.try_get("device_id")?,
                    event_id: row.try_get("event_id")?,
                    created_at_ms: row.try_get("created_at_ms")?,
                    size: row.try_get("size")?,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(StoreError::Sql)
    }

    fn blob_path(&self, app_id: &str, root_id: &str, device_id: &str, event_id: &str) -> PathBuf {
        self.blob_base_dir
            .join(app_id)
            .join(root_id)
            .join(device_id)
            .join(format!("{event_id}.blob"))
    }
}

async fn write_staged_blob(staged_path: &Path, body: &Bytes) -> Result<(), StoreError> {
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(staged_path)
        .await?;

    file.write_all(body).await?;
    file.sync_all().await?;

    Ok(())
}

/// Flushes the directory entry so a published blob survives power loss, not
/// just the file contents that `sync_all` already covers.
#[cfg(unix)]
async fn sync_parent_dir(path: &Path) -> Result<(), StoreError> {
    if let Some(parent) = path.parent() {
        tokio::fs::File::open(parent).await?.sync_all().await?;
    }

    Ok(())
}

#[cfg(not(unix))]
async fn sync_parent_dir(_path: &Path) -> Result<(), StoreError> {
    Ok(())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(
        error,
        sqlx::Error::Database(database_error)
            if database_error.is_unique_violation()
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode};
    use tempfile::TempDir;

    use super::*;

    async fn test_store() -> (Store, TempDir) {
        let dir = TempDir::new().expect("temp dir");
        let config = Config {
            listen_addr: "127.0.0.1:0".parse().expect("socket address"),
            blob_base_dir: dir.path().join("blobs"),
            secret_registry_path: dir.path().join("secrets.json"),
            database_options: SqliteConnectOptions::new()
                .filename(dir.path().join("gesh.db"))
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal)
                .busy_timeout(Duration::from_secs(5)),
            upload_limit_bytes: 1024,
        };

        (Store::open(&config).await.expect("store opens"), dir)
    }

    /// Simulates a process that died after publishing ciphertext but before its
    /// metadata row committed.
    async fn write_orphan_blob(store: &Store, body: &[u8]) {
        let path = store.blob_path("app", "root", "device", "event");
        tokio::fs::create_dir_all(path.parent().expect("parent"))
            .await
            .expect("create dirs");
        tokio::fs::write(&path, body).await.expect("write orphan");
    }

    #[tokio::test]
    async fn reuploading_an_event_id_conflicts() {
        let (store, _dir) = test_store().await;

        store
            .put_event("app", "root", "device", "event", Bytes::from_static(b"one"))
            .await
            .expect("first upload succeeds");

        let err = store
            .put_event("app", "root", "device", "event", Bytes::from_static(b"two"))
            .await
            .expect_err("second upload is rejected");

        assert!(matches!(err, StoreError::Conflict));
    }

    #[tokio::test]
    async fn interrupted_upload_can_be_retried() {
        let (store, _dir) = test_store().await;
        write_orphan_blob(&store, b"partial").await;

        let metadata = store
            .put_event(
                "app",
                "root",
                "device",
                "event",
                Bytes::from_static(b"complete"),
            )
            .await
            .expect("retry reclaims the uncommitted blob");

        assert_eq!(metadata.size, 8);

        let stored = store
            .get_event("app", "root", "device", "event")
            .await
            .expect("event is readable");
        assert_eq!(stored, Bytes::from_static(b"complete"));

        let events = store
            .list_events("app", "root", 0, 10, None)
            .await
            .expect("listing succeeds");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, "event");
    }

    #[tokio::test]
    async fn uncommitted_blob_is_not_served() {
        let (store, _dir) = test_store().await;
        write_orphan_blob(&store, b"partial").await;

        let err = store
            .get_event("app", "root", "device", "event")
            .await
            .expect_err("an unreferenced blob does not exist");

        assert!(matches!(err, StoreError::NotFound));
    }
}
