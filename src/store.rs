use std::{path::PathBuf, time::{SystemTime, UNIX_EPOCH}};

use bytes::Bytes;
use serde::Serialize;
use sqlx::{Row, SqlitePool, sqlite::SqlitePoolOptions};
use thiserror::Error;
use tokio::io::AsyncWriteExt;

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

        if let Some(parent) = config
            .database_options
            .get_filename()
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            tokio::fs::create_dir_all(parent).await?;
        }

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

        let mut file = match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await
        {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(StoreError::Conflict);
            }
            Err(err) => return Err(StoreError::Io(err)),
        };

        if let Err(err) = file.write_all(&body).await {
            let _ = tokio::fs::remove_file(&path).await;
            return Err(StoreError::Io(err));
        }
        if let Err(err) = file.sync_all().await {
            let _ = tokio::fs::remove_file(&path).await;
            return Err(StoreError::Io(err));
        }

        let created_at_ms = now_ms();
        let size = body.len() as i64;

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
        .execute(&self.pool)
        .await;

        let result = match result {
            Ok(result) => result,
            Err(err) => {
                let _ = tokio::fs::remove_file(&path).await;
                if is_unique_violation(&err) {
                    return Err(StoreError::Conflict);
                }
                return Err(StoreError::Sql(err));
            }
        };

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
