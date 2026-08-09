use std::{env, net::SocketAddr, path::PathBuf, str::FromStr, time::Duration};

use anyhow::{Context, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode};

#[derive(Clone, Debug)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub blob_base_dir: PathBuf,
    pub secret_registry_path: PathBuf,
    pub database_options: SqliteConnectOptions,
    pub upload_limit_bytes: usize,
    pub retention: Retention,
    /// How long an enrollment code stays redeemable. Short by design: a code is
    /// typed by a person and is the one credential that is not high-entropy.
    pub enrollment_code_ttl: Duration,
}

/// How long a relay holds data it has already passed on.
///
/// GESH is a relay, not a record: an event exists to be handed to the other
/// devices on a root and should not outlive that errand. Ciphertext is dropped
/// once every active peer has acknowledged it, and `event_ttl` bounds the wait
/// when a peer never returns to collect it.
#[derive(Clone, Debug)]
pub struct Retention {
    /// Maximum age of an event whose peers have not all acknowledged it.
    pub event_ttl: Duration,
    /// How long a deleted event's identifier stays reserved, so that already
    /// relayed ciphertext cannot be replayed back onto the root.
    pub tombstone_ttl: Duration,
    /// How long a silent device still counts as a peer that must acknowledge
    /// an event before it can be dropped.
    pub device_ttl: Duration,
    /// Delay between reclamation passes.
    pub sweep_interval: Duration,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let listen_addr = env::var("GESH_LISTEN_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:3000".to_string())
            .parse()
            .context("GESH_LISTEN_ADDR must be a valid socket address")?;

        let blob_base_dir = env::var("GESH_BLOB_BASE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("data/blobs"));

        let secret_registry_path = env::var("GESH_SECRET_REGISTRY_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("data/secrets.json"));

        let database_url =
            env::var("GESH_DATABASE_URL").unwrap_or_else(|_| "sqlite://data/gesh.db".to_string());
        let database_options = SqliteConnectOptions::from_str(&database_url)
            .context("GESH_DATABASE_URL must be a valid SQLite URL")?
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_secs(5));

        let upload_limit_bytes = env::var("GESH_UPLOAD_LIMIT_BYTES")
            .unwrap_or_else(|_| (32 * 1024 * 1024).to_string())
            .parse::<usize>()
            .context("GESH_UPLOAD_LIMIT_BYTES must be a positive integer")?;

        if upload_limit_bytes == 0 {
            anyhow::bail!("GESH_UPLOAD_LIMIT_BYTES must be greater than zero");
        }

        let retention = Retention {
            event_ttl: duration_from_env("GESH_EVENT_TTL_SECONDS", 7 * 24 * 60 * 60)?,
            tombstone_ttl: duration_from_env("GESH_TOMBSTONE_TTL_SECONDS", 30 * 24 * 60 * 60)?,
            device_ttl: duration_from_env("GESH_DEVICE_TTL_SECONDS", 30 * 24 * 60 * 60)?,
            sweep_interval: duration_from_env("GESH_SWEEP_INTERVAL_SECONDS", 60)?,
        };

        if retention.sweep_interval.is_zero() {
            anyhow::bail!("GESH_SWEEP_INTERVAL_SECONDS must be greater than zero");
        }

        let enrollment_code_ttl = duration_from_env("GESH_ENROLLMENT_CODE_TTL_SECONDS", 10 * 60)?;

        Ok(Self {
            listen_addr,
            blob_base_dir,
            secret_registry_path,
            database_options,
            upload_limit_bytes,
            retention,
            enrollment_code_ttl,
        })
    }
}

fn duration_from_env(key: &'static str, default_seconds: u64) -> Result<Duration> {
    let seconds = env::var(key)
        .unwrap_or_else(|_| default_seconds.to_string())
        .parse::<u64>()
        .with_context(|| format!("{key} must be a whole number of seconds"))?;

    Ok(Duration::from_secs(seconds))
}
