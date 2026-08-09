use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use serde::Serialize;
use sqlx::{Row, SqlitePool, sqlite::SqlitePoolOptions};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::{
    config::{Config, Retention},
    credentials::{DeviceToken, EnrollmentCode, hash_code},
};

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

#[derive(Debug, Clone, Serialize)]
pub struct RootRef {
    pub app_id: String,
    pub root_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnrolledDevice {
    pub app_id: String,
    pub root_id: String,
    pub device_id: String,
    pub token: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnrolledDeviceSummary {
    pub device_id: String,
    pub enrolled_at_ms: i64,
    pub last_seen_ms: Option<i64>,
    pub ack_cursor: Option<i64>,
}

/// What a root looks like the moment it is created, and the only time its
/// credentials are ever recoverable.
///
/// Two tokens rather than one, because the source app plays two parts. It is
/// the authority that enrolls and revokes, and it is also just another device
/// relaying its own events. Keeping those apart means the credential doing the
/// day-to-day sync cannot revoke anybody.
#[derive(Debug, Clone, Serialize)]
pub struct ProvisionedRoot {
    pub app_id: String,
    pub root_id: String,
    pub handle: Option<String>,
    pub device_id: String,
    pub root_token: String,
    pub device_token: String,
}

/// What a credential is allowed to do.
///
/// This is the privilege boundary the whole pairing model rests on, so it is
/// stored explicitly rather than inferred from which table a row sits in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialRole {
    Root,
    Device,
}

impl CredentialRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Device => "device",
        }
    }

    /// Anything that is not explicitly the authority is treated as a device,
    /// so an unreadable row can only ever lose privilege.
    fn from_stored(value: &str) -> Self {
        if value == Self::Root.as_str() {
            Self::Root
        } else {
            Self::Device
        }
    }
}

/// The `device_id` a root credential is filed under.
///
/// A root credential is not held on behalf of any device, but the table's
/// uniqueness rule is `(app_id, root_id, device_id)`, and reusing it here is
/// what limits a root to exactly one authority credential. The `@` guarantees
/// no real device can collide with it: [`crate::ids::is_valid_id`] rejects the
/// character, so no such `device_id` can ever arrive from a request.
const ROOT_CREDENTIAL_HOLDER: &str = "@root";

/// A credential as stored, for the authenticator to verify a presented secret
/// against. The secret itself was never kept.
#[derive(Debug, Clone)]
pub struct StoredCredential {
    pub app_id: String,
    pub root_id: String,
    pub device_id: String,
    pub secret_hash: Vec<u8>,
    pub role: CredentialRole,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceState {
    pub device_id: String,
    pub ack_cursor: i64,
    pub last_seen_ms: i64,
}

/// What a single reclamation pass reclaimed.
#[derive(Debug, Default, Clone, Copy)]
pub struct SweepReport {
    pub delivered: u64,
    pub expired: u64,
    pub blobs_removed: u64,
    pub tombstones_purged: u64,
    pub devices_forgotten: u64,
    pub codes_expired: u64,
}

impl SweepReport {
    pub fn is_empty(&self) -> bool {
        self.delivered == 0
            && self.expired == 0
            && self.blobs_removed == 0
            && self.tombstones_purged == 0
            && self.devices_forgotten == 0
            && self.codes_expired == 0
    }
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

        migrate(&pool).await?;

        Ok(Self {
            pool,
            blob_base_dir: config.blob_base_dir.clone(),
        })
    }

    /// Creates a root and hands its credentials back exactly once.
    ///
    /// This is what replaces an administrator hand-writing a secret registry.
    /// The app that calls it becomes the authority for the root it just made:
    /// nothing else can enroll a device onto it or revoke one from it. The
    /// server chooses the root identifier so that two apps provisioning at the
    /// same moment cannot land on the same one.
    pub async fn provision_root(
        &self,
        app_id: &str,
        device_id: &str,
        handle: Option<&str>,
    ) -> Result<ProvisionedRoot, StoreError> {
        let root_id = format!("root_{}", Uuid::new_v4());
        let root_token = DeviceToken::mint();
        let device_token = DeviceToken::mint();
        let now = now_ms();

        let mut tx = self.pool.begin().await?;

        if let Some(handle) = handle {
            let named = sqlx::query(
                r#"
                INSERT INTO roots(app_id, root_id, handle, created_at_ms)
                VALUES (?, ?, ?, ?)
                "#,
            )
            .bind(app_id)
            .bind(&root_id)
            .bind(handle)
            .bind(now)
            .execute(&mut *tx)
            .await;

            match named {
                Ok(_) => {}
                Err(err) if is_unique_violation(&err) => return Err(StoreError::Conflict),
                Err(err) => return Err(StoreError::Sql(err)),
            }
        }

        for (token, holder, role) in [
            (&root_token, ROOT_CREDENTIAL_HOLDER, CredentialRole::Root),
            (&device_token, device_id, CredentialRole::Device),
        ] {
            sqlx::query(
                r#"
                INSERT INTO device_credentials(
                    token_id, app_id, root_id, device_id, secret_hash, role, created_at_ms
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&token.token_id)
            .bind(app_id)
            .bind(&root_id)
            .bind(holder)
            .bind(token.secret_hash())
            .bind(role.as_str())
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        Ok(ProvisionedRoot {
            app_id: app_id.to_owned(),
            root_id,
            handle: handle.map(str::to_owned),
            device_id: device_id.to_owned(),
            root_token: root_token.presentation(),
            device_token: device_token.presentation(),
        })
    }

    /// Publishes the name a device can use to find this root before it holds
    /// any credential for it.
    pub async fn set_handle(
        &self,
        app_id: &str,
        root_id: &str,
        handle: &str,
    ) -> Result<(), StoreError> {
        let result = sqlx::query(
            r#"
            INSERT INTO roots(app_id, root_id, handle, created_at_ms)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(app_id, root_id) DO UPDATE SET handle = excluded.handle
            "#,
        )
        .bind(app_id)
        .bind(root_id)
        .bind(handle)
        .bind(now_ms())
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => Ok(()),
            Err(err) if is_unique_violation(&err) => Err(StoreError::Conflict),
            Err(err) => Err(StoreError::Sql(err)),
        }
    }

    pub async fn resolve_handle(&self, handle: &str) -> Result<RootRef, StoreError> {
        let row = sqlx::query("SELECT app_id, root_id FROM roots WHERE handle = ?")
            .bind(handle)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(StoreError::NotFound)?;

        Ok(RootRef {
            app_id: row.try_get("app_id")?,
            root_id: row.try_get("root_id")?,
        })
    }

    /// Issues a one-time code that lets a device join this root.
    ///
    /// Only the hash is kept, so a leaked database cannot be used to enroll.
    pub async fn create_enrollment_code(
        &self,
        app_id: &str,
        root_id: &str,
        code: &EnrollmentCode,
        ttl: Duration,
    ) -> Result<i64, StoreError> {
        let now = now_ms();
        let expires_at_ms = now + millis(ttl);

        sqlx::query(
            r#"
            INSERT INTO enrollment_codes(code_hash, app_id, root_id, expires_at_ms, created_at_ms)
            VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(code.hash())
        .bind(app_id)
        .bind(root_id)
        .bind(expires_at_ms)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(expires_at_ms)
    }

    /// Exchanges a valid code for a device's own credential.
    ///
    /// The code is consumed inside the same transaction that mints the
    /// credential, so a code cannot enroll two devices even if it is redeemed
    /// twice concurrently.
    pub async fn redeem_enrollment_code(
        &self,
        code: &str,
        device_id: &str,
    ) -> Result<EnrolledDevice, StoreError> {
        let mut tx = self.pool.begin().await?;

        let row = sqlx::query(
            r#"
            DELETE FROM enrollment_codes
            WHERE code_hash = ? AND expires_at_ms > ?
            RETURNING app_id, root_id
            "#,
        )
        .bind(hash_code(code))
        .bind(now_ms())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StoreError::NotFound)?;

        let app_id: String = row.try_get("app_id")?;
        let root_id: String = row.try_get("root_id")?;

        let token = DeviceToken::mint();

        // Re-enrolling a device replaces its credential, which is what makes a
        // reinstalled phone recoverable without a second device identity.
        sqlx::query(
            r#"
            INSERT INTO device_credentials(
                token_id, app_id, root_id, device_id, secret_hash, role, created_at_ms
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(app_id, root_id, device_id) DO UPDATE SET
                token_id = excluded.token_id,
                secret_hash = excluded.secret_hash,
                created_at_ms = excluded.created_at_ms
            "#,
        )
        .bind(&token.token_id)
        .bind(&app_id)
        .bind(&root_id)
        .bind(device_id)
        .bind(token.secret_hash())
        .bind(CredentialRole::Device.as_str())
        .bind(now_ms())
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(EnrolledDevice {
            app_id,
            root_id,
            device_id: device_id.to_owned(),
            token: token.presentation(),
        })
    }

    /// Finds the credential a presented token claims to be, for the caller to
    /// verify. Returns the scope it grants alongside the stored hash.
    pub async fn credential(&self, token_id: &str) -> Result<Option<StoredCredential>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT app_id, root_id, device_id, secret_hash, role FROM device_credentials
            WHERE token_id = ?
            "#,
        )
        .bind(token_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        Ok(Some(StoredCredential {
            app_id: row.try_get("app_id")?,
            root_id: row.try_get("root_id")?,
            device_id: row.try_get("device_id")?,
            secret_hash: row.try_get("secret_hash")?,
            role: CredentialRole::from_stored(row.try_get::<String, _>("role")?.as_str()),
        }))
    }

    pub async fn list_devices(
        &self,
        app_id: &str,
        root_id: &str,
    ) -> Result<Vec<EnrolledDeviceSummary>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT credential.device_id, credential.created_at_ms, device.last_seen_ms,
                   device.ack_cursor
            FROM device_credentials credential
            LEFT JOIN devices device
              ON device.app_id = credential.app_id
             AND device.root_id = credential.root_id
             AND device.device_id = credential.device_id
            WHERE credential.app_id = ? AND credential.root_id = ?
              AND credential.role = 'device'
            ORDER BY credential.created_at_ms ASC
            "#,
        )
        .bind(app_id)
        .bind(root_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                Ok(EnrolledDeviceSummary {
                    device_id: row.try_get("device_id")?,
                    enrolled_at_ms: row.try_get("created_at_ms")?,
                    last_seen_ms: row.try_get("last_seen_ms")?,
                    ack_cursor: row.try_get("ack_cursor")?,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .map_err(StoreError::Sql)
    }

    /// Withdraws a device's access.
    ///
    /// Its peer record goes with it, so a revoked device immediately stops
    /// being something the relay waits for before erasing data.
    ///
    /// Only device credentials can be withdrawn this way. The root's own
    /// credential is filed under a `device_id` no request can express, and the
    /// role check below says so a second time: revocation must never be able to
    /// leave a root with no authority over itself.
    pub async fn revoke_device(
        &self,
        app_id: &str,
        root_id: &str,
        device_id: &str,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;

        let result = sqlx::query(
            r#"
            DELETE FROM device_credentials
            WHERE app_id = ? AND root_id = ? AND device_id = ? AND role = 'device'
            "#,
        )
        .bind(app_id)
        .bind(root_id)
        .bind(device_id)
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }

        sqlx::query("DELETE FROM devices WHERE app_id = ? AND root_id = ? AND device_id = ?")
            .bind(app_id)
            .bind(root_id)
            .bind(device_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        Ok(())
    }

    /// Records how far a device has consumed the feed.
    ///
    /// This is what lets the relay know an event has finished its errand: once
    /// every active peer has acknowledged past an event, nothing is waiting for
    /// it and the ciphertext can be dropped.
    pub async fn acknowledge(
        &self,
        app_id: &str,
        root_id: &str,
        device_id: &str,
        ack_cursor: i64,
    ) -> Result<DeviceState, StoreError> {
        self.touch_device(app_id, root_id, device_id, ack_cursor)
            .await?;

        let row = sqlx::query(
            r#"
            SELECT ack_cursor, last_seen_ms FROM devices
            WHERE app_id = ? AND root_id = ? AND device_id = ?
            "#,
        )
        .bind(app_id)
        .bind(root_id)
        .bind(device_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(DeviceState {
            device_id: device_id.to_owned(),
            ack_cursor: row.try_get("ack_cursor")?,
            last_seen_ms: row.try_get("last_seen_ms")?,
        })
    }

    /// Registers a device as an active peer and advances its acknowledgement.
    ///
    /// Acknowledgements only ever move forward, so a stale or retried report
    /// cannot rewind a device's progress and cause data to be held again.
    async fn touch_device(
        &self,
        app_id: &str,
        root_id: &str,
        device_id: &str,
        ack_cursor: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            INSERT INTO devices(app_id, root_id, device_id, ack_cursor, last_seen_ms)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(app_id, root_id, device_id) DO UPDATE SET
                ack_cursor = MAX(ack_cursor, excluded.ack_cursor),
                last_seen_ms = excluded.last_seen_ms
            "#,
        )
        .bind(app_id)
        .bind(root_id)
        .bind(device_id)
        .bind(ack_cursor)
        .bind(now_ms())
        .execute(&self.pool)
        .await?;

        Ok(())
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
            return result;
        }

        // Registers the uploader as an active peer, without advancing its
        // acknowledgement: producing an event says nothing about having
        // consumed the events its peers produced earlier.
        self.touch_device(app_id, root_id, device_id, 0).await?;

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
              AND deleted_at_ms IS NULL
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
                  AND deleted_at_ms IS NULL
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
                  AND deleted_at_ms IS NULL
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

    /// Reclaims everything the relay is no longer obliged to hold.
    ///
    /// Runs in four stages, each idempotent so an interrupted pass simply
    /// resumes on the next one: retire delivered events, retire events that
    /// outlived `event_ttl`, erase the ciphertext of retired events, then drop
    /// the tombstones and device records that have themselves expired.
    pub async fn sweep(&self, retention: &Retention) -> Result<SweepReport, StoreError> {
        let now = now_ms();

        Ok(SweepReport {
            delivered: self.retire_delivered(now, retention).await?,
            expired: self
                .retire_older_than(now, now - millis(retention.event_ttl))
                .await?,
            blobs_removed: self.erase_retired_blobs().await?,
            tombstones_purged: self
                .purge_tombstones(now - millis(retention.tombstone_ttl))
                .await?,
            devices_forgotten: self
                .forget_devices(now - millis(retention.device_ttl))
                .await?,
            codes_expired: self.purge_expired_codes(now).await?,
        })
    }

    /// Retires events every active peer has acknowledged.
    ///
    /// A device never has to acknowledge its own upload, and an event with no
    /// active peer at all is left alone: nothing has collected it yet, so the
    /// only thing that may retire it is [`Self::retire_older_than`].
    async fn retire_delivered(&self, now: i64, retention: &Retention) -> Result<u64, StoreError> {
        let active_since = now - millis(retention.device_ttl);

        let result = sqlx::query(
            r#"
            UPDATE events SET deleted_at_ms = ?
            WHERE deleted_at_ms IS NULL
              AND EXISTS (
                  SELECT 1 FROM devices peer
                  WHERE peer.app_id = events.app_id
                    AND peer.root_id = events.root_id
                    AND peer.device_id <> events.device_id
                    AND peer.last_seen_ms >= ?
              )
              AND NOT EXISTS (
                  SELECT 1 FROM devices peer
                  WHERE peer.app_id = events.app_id
                    AND peer.root_id = events.root_id
                    AND peer.device_id <> events.device_id
                    AND peer.last_seen_ms >= ?
                    AND peer.ack_cursor < events.cursor
              )
            "#,
        )
        .bind(now)
        .bind(active_since)
        .bind(active_since)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    async fn retire_older_than(&self, now: i64, cutoff_ms: i64) -> Result<u64, StoreError> {
        let result = sqlx::query(
            r#"
            UPDATE events SET deleted_at_ms = ?
            WHERE deleted_at_ms IS NULL AND created_at_ms <= ?
            "#,
        )
        .bind(now)
        .bind(cutoff_ms)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Erases the ciphertext of retired events, leaving the row as a tombstone.
    ///
    /// The row is cleared only after the file is gone, so a crash mid-pass
    /// leaves the event to be retried rather than a row claiming ciphertext was
    /// erased when it is still on disk.
    async fn erase_retired_blobs(&self) -> Result<u64, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT cursor, app_id, root_id, device_id, event_id FROM events
            WHERE deleted_at_ms IS NOT NULL AND blob_present = 1
            LIMIT 1000
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut removed = 0;

        for row in rows {
            let cursor: i64 = row.try_get("cursor")?;
            let path = self.blob_path(
                row.try_get::<String, _>("app_id")?.as_str(),
                row.try_get::<String, _>("root_id")?.as_str(),
                row.try_get::<String, _>("device_id")?.as_str(),
                row.try_get::<String, _>("event_id")?.as_str(),
            );

            match tokio::fs::remove_file(&path).await {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(StoreError::Io(err)),
            }

            sqlx::query("UPDATE events SET blob_present = 0, size = 0 WHERE cursor = ?")
                .bind(cursor)
                .execute(&self.pool)
                .await?;

            removed += 1;
        }

        Ok(removed)
    }

    /// Releases event identifiers whose tombstones have expired.
    ///
    /// Until this runs, a relayed event cannot be uploaded again under the same
    /// identifier, which is what stops captured ciphertext being replayed onto
    /// a root after it was delivered and erased.
    async fn purge_tombstones(&self, cutoff_ms: i64) -> Result<u64, StoreError> {
        let result = sqlx::query(
            r#"
            DELETE FROM events
            WHERE deleted_at_ms IS NOT NULL AND blob_present = 0 AND deleted_at_ms <= ?
            "#,
        )
        .bind(cutoff_ms)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Drops codes that can no longer be redeemed, so an unused pairing
    /// attempt does not linger as a stored hash.
    async fn purge_expired_codes(&self, now: i64) -> Result<u64, StoreError> {
        let result = sqlx::query("DELETE FROM enrollment_codes WHERE expires_at_ms <= ?")
            .bind(now)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }

    async fn forget_devices(&self, cutoff_ms: i64) -> Result<u64, StoreError> {
        let result = sqlx::query("DELETE FROM devices WHERE last_seen_ms <= ?")
            .bind(cutoff_ms)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }

    fn blob_path(&self, app_id: &str, root_id: &str, device_id: &str, event_id: &str) -> PathBuf {
        self.blob_base_dir
            .join(app_id)
            .join(root_id)
            .join(device_id)
            .join(format!("{event_id}.blob"))
    }
}

async fn migrate(pool: &SqlitePool) -> Result<(), StoreError> {
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
            deleted_at_ms INTEGER,
            blob_present INTEGER NOT NULL DEFAULT 1,
            UNIQUE(app_id, root_id, device_id, event_id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Databases created before retention existed predate the two columns above.
    let columns: Vec<String> = sqlx::query("PRAGMA table_info(events)")
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|row| row.get::<String, _>("name"))
        .collect();

    if !columns.iter().any(|name| name == "deleted_at_ms") {
        sqlx::query("ALTER TABLE events ADD COLUMN deleted_at_ms INTEGER")
            .execute(pool)
            .await?;
    }

    if !columns.iter().any(|name| name == "blob_present") {
        sqlx::query("ALTER TABLE events ADD COLUMN blob_present INTEGER NOT NULL DEFAULT 1")
            .execute(pool)
            .await?;
    }

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS devices (
            app_id TEXT NOT NULL,
            root_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            ack_cursor INTEGER NOT NULL DEFAULT 0,
            last_seen_ms INTEGER NOT NULL,
            PRIMARY KEY(app_id, root_id, device_id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS roots (
            app_id TEXT NOT NULL,
            root_id TEXT NOT NULL,
            handle TEXT NOT NULL UNIQUE,
            created_at_ms INTEGER NOT NULL,
            PRIMARY KEY(app_id, root_id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS device_credentials (
            token_id TEXT PRIMARY KEY,
            app_id TEXT NOT NULL,
            root_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            secret_hash BLOB NOT NULL,
            role TEXT NOT NULL DEFAULT 'device',
            created_at_ms INTEGER NOT NULL,
            UNIQUE(app_id, root_id, device_id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Databases created before roots could provision themselves hold only
    // device credentials, which is exactly what the default says.
    let credential_columns: Vec<String> = sqlx::query("PRAGMA table_info(device_credentials)")
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|row| row.get::<String, _>("name"))
        .collect();

    if !credential_columns.iter().any(|name| name == "role") {
        sqlx::query(
            "ALTER TABLE device_credentials ADD COLUMN role TEXT NOT NULL DEFAULT 'device'",
        )
        .execute(pool)
        .await?;
    }

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS enrollment_codes (
            code_hash BLOB PRIMARY KEY,
            app_id TEXT NOT NULL,
            root_id TEXT NOT NULL,
            expires_at_ms INTEGER NOT NULL,
            created_at_ms INTEGER NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_events_root_cursor
        ON events(app_id, root_id, cursor)
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_events_reclaimable
        ON events(deleted_at_ms, blob_present)
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
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

fn millis(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
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

    use crate::{
        config::Limits,
        credentials::{split_token, verify_secret},
    };

    use super::*;

    fn retention() -> Retention {
        Retention {
            event_ttl: Duration::from_secs(7 * 24 * 60 * 60),
            tombstone_ttl: Duration::from_secs(30 * 24 * 60 * 60),
            device_ttl: Duration::from_secs(30 * 24 * 60 * 60),
            sweep_interval: Duration::from_secs(60),
        }
    }

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
            retention: retention(),
            enrollment_code_ttl: Duration::from_secs(600),
            provisioning_secret: None,
            public_url: None,
            limits: Limits {
                enroll_attempts_per_minute: 10,
                roots_per_minute: 5,
                handle_lookups_per_minute: 60,
                failures_before_backoff: 5,
                max_backoff: Duration::from_secs(300),
                trusted_forwarded_header: None,
            },
        };

        (Store::open(&config).await.expect("store opens"), dir)
    }

    async fn upload(store: &Store, device_id: &str, event_id: &str) -> EventMetadata {
        store
            .put_event(
                "app",
                "root",
                device_id,
                event_id,
                Bytes::from_static(b"ciphertext"),
            )
            .await
            .expect("upload succeeds")
    }

    /// Backdates an event so TTL rules can be exercised without sleeping.
    async fn age_event(store: &Store, cursor: i64, age: Duration) {
        sqlx::query("UPDATE events SET created_at_ms = ? WHERE cursor = ?")
            .bind(now_ms() - millis(age))
            .bind(cursor)
            .execute(&store.pool)
            .await
            .expect("backdate event");
    }

    async fn blob_exists(store: &Store, device_id: &str, event_id: &str) -> bool {
        tokio::fs::try_exists(store.blob_path("app", "root", device_id, event_id))
            .await
            .expect("check blob")
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
    async fn event_is_reclaimed_once_every_peer_acknowledges_it() {
        let (store, _dir) = test_store().await;
        let event = upload(&store, "phone", "receipt").await;

        // The desktop registers as a peer but has not caught up yet.
        store
            .acknowledge("app", "root", "desktop", event.cursor - 1)
            .await
            .expect("ack succeeds");
        let report = store.sweep(&retention()).await.expect("sweep succeeds");
        assert_eq!(report.delivered, 0);
        assert!(blob_exists(&store, "phone", "receipt").await);

        store
            .acknowledge("app", "root", "desktop", event.cursor)
            .await
            .expect("ack succeeds");
        let report = store.sweep(&retention()).await.expect("sweep succeeds");

        assert_eq!(report.delivered, 1);
        assert_eq!(report.blobs_removed, 1);
        assert!(!blob_exists(&store, "phone", "receipt").await);
        assert!(matches!(
            store.get_event("app", "root", "phone", "receipt").await,
            Err(StoreError::NotFound)
        ));
        assert!(
            store
                .list_events("app", "root", 0, 10, None)
                .await
                .expect("listing succeeds")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn event_is_kept_while_no_peer_has_collected_it() {
        let (store, _dir) = test_store().await;
        upload(&store, "phone", "receipt").await;

        let report = store.sweep(&retention()).await.expect("sweep succeeds");

        assert_eq!(report.delivered, 0);
        assert!(blob_exists(&store, "phone", "receipt").await);
    }

    #[tokio::test]
    async fn unclaimed_event_expires_after_its_ttl() {
        let (store, _dir) = test_store().await;
        let event = upload(&store, "phone", "receipt").await;
        age_event(&store, event.cursor, Duration::from_secs(8 * 24 * 60 * 60)).await;

        let report = store.sweep(&retention()).await.expect("sweep succeeds");

        assert_eq!(report.expired, 1);
        assert_eq!(report.blobs_removed, 1);
        assert!(!blob_exists(&store, "phone", "receipt").await);
    }

    #[tokio::test]
    async fn relayed_event_cannot_be_replayed_while_tombstoned() {
        let (store, _dir) = test_store().await;
        let event = upload(&store, "phone", "receipt").await;
        store
            .acknowledge("app", "root", "desktop", event.cursor)
            .await
            .expect("ack succeeds");
        store.sweep(&retention()).await.expect("sweep succeeds");

        let err = store
            .put_event(
                "app",
                "root",
                "phone",
                "receipt",
                Bytes::from_static(b"replayed"),
            )
            .await
            .expect_err("a relayed event cannot return");

        assert!(matches!(err, StoreError::Conflict));
        assert!(!blob_exists(&store, "phone", "receipt").await);
    }

    #[tokio::test]
    async fn a_silent_device_stops_holding_data_back() {
        let (store, _dir) = test_store().await;
        upload(&store, "phone", "receipt").await;
        store
            .acknowledge("app", "root", "desktop", 0)
            .await
            .expect("ack succeeds");

        // The desktop goes quiet for longer than the device TTL.
        sqlx::query("UPDATE devices SET last_seen_ms = ? WHERE device_id = 'desktop'")
            .bind(now_ms() - millis(Duration::from_secs(31 * 24 * 60 * 60)))
            .execute(&store.pool)
            .await
            .expect("backdate device");

        let report = store.sweep(&retention()).await.expect("sweep succeeds");

        // Nothing is holding the event, but nothing has collected it either, so
        // it waits for its TTL rather than being dropped.
        assert_eq!(report.delivered, 0);
        assert_eq!(report.devices_forgotten, 1);
        assert!(blob_exists(&store, "phone", "receipt").await);
    }

    #[tokio::test]
    async fn a_code_pairs_exactly_one_device_once() {
        let (store, _dir) = test_store().await;
        store
            .set_handle("app", "root", "madsen-home")
            .await
            .expect("handle is set");

        let resolved = store
            .resolve_handle("madsen-home")
            .await
            .expect("handle resolves");
        assert_eq!(resolved.app_id, "app");
        assert_eq!(resolved.root_id, "root");

        let code = EnrollmentCode::mint();
        store
            .create_enrollment_code("app", "root", &code, Duration::from_secs(600))
            .await
            .expect("code is minted");

        let enrolled = store
            .redeem_enrollment_code(&code.code, "phone")
            .await
            .expect("code redeems");
        assert_eq!(enrolled.device_id, "phone");

        // The minted token verifies, and only against its own credential.
        let (token_id, secret) = split_token(&enrolled.token).expect("token splits");
        let stored = store
            .credential(token_id)
            .await
            .expect("lookup succeeds")
            .expect("credential exists");
        assert_eq!(stored.device_id, "phone");
        assert!(verify_secret(secret, &stored.secret_hash));
        assert!(!verify_secret("guessed", &stored.secret_hash));

        // A code is spent by the device that used it.
        assert!(matches!(
            store.redeem_enrollment_code(&code.code, "laptop").await,
            Err(StoreError::NotFound)
        ));
    }

    #[tokio::test]
    async fn an_expired_code_no_longer_pairs() {
        let (store, _dir) = test_store().await;
        let code = EnrollmentCode::mint();
        store
            .create_enrollment_code("app", "root", &code, Duration::from_secs(600))
            .await
            .expect("code is minted");

        sqlx::query("UPDATE enrollment_codes SET expires_at_ms = ?")
            .bind(now_ms() - 1)
            .execute(&store.pool)
            .await
            .expect("expire code");

        assert!(matches!(
            store.redeem_enrollment_code(&code.code, "phone").await,
            Err(StoreError::NotFound)
        ));
    }

    #[tokio::test]
    async fn revoking_a_device_withdraws_only_that_device() {
        let (store, _dir) = test_store().await;

        let mut tokens = Vec::new();
        for device_id in ["phone", "laptop"] {
            let code = EnrollmentCode::mint();
            store
                .create_enrollment_code("app", "root", &code, Duration::from_secs(600))
                .await
                .expect("code is minted");
            tokens.push(
                store
                    .redeem_enrollment_code(&code.code, device_id)
                    .await
                    .expect("code redeems"),
            );
        }

        store
            .acknowledge("app", "root", "phone", 0)
            .await
            .expect("ack succeeds");
        store
            .revoke_device("app", "root", "phone")
            .await
            .expect("revocation succeeds");

        // The revoked credential is gone, and so is its claim on retained data.
        let (revoked_id, _) = split_token(&tokens[0].token).expect("token splits");
        assert!(
            store
                .credential(revoked_id)
                .await
                .expect("lookup succeeds")
                .is_none()
        );

        let devices = store
            .list_devices("app", "root")
            .await
            .expect("listing succeeds");
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_id, "laptop");

        // The other device is untouched.
        let (kept_id, kept_secret) = split_token(&tokens[1].token).expect("token splits");
        let stored = store
            .credential(kept_id)
            .await
            .expect("lookup succeeds")
            .expect("credential exists");
        assert!(verify_secret(kept_secret, &stored.secret_hash));

        assert!(matches!(
            store.revoke_device("app", "root", "phone").await,
            Err(StoreError::NotFound)
        ));
    }

    #[tokio::test]
    async fn a_handle_belongs_to_one_root() {
        let (store, _dir) = test_store().await;
        store
            .set_handle("app", "root", "madsen-home")
            .await
            .expect("handle is set");

        assert!(matches!(
            store.set_handle("app", "other", "madsen-home").await,
            Err(StoreError::Conflict)
        ));
        assert!(matches!(
            store.resolve_handle("nobody-home").await,
            Err(StoreError::NotFound)
        ));
    }

    #[tokio::test]
    async fn acknowledgements_only_move_forward() {
        let (store, _dir) = test_store().await;

        store
            .acknowledge("app", "root", "desktop", 12)
            .await
            .expect("ack succeeds");
        let state = store
            .acknowledge("app", "root", "desktop", 4)
            .await
            .expect("ack succeeds");

        assert_eq!(state.ack_cursor, 12);
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
