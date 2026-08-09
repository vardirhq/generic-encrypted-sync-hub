use std::{env, net::SocketAddr, path::PathBuf, str::FromStr, time::Duration};

use anyhow::{Context, Result};
use http::HeaderName;
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
    /// Required of anyone creating a root, when set.
    ///
    /// Unset by default, because the point of self-provisioning is that
    /// installing an app is the whole setup. The default bind is localhost, so
    /// "anyone" means anyone already on the host. A deployment reachable from
    /// further away should set this and close the door behind its own devices.
    pub provisioning_secret: Option<String>,
    /// The address clients reach this server on, used to build the pairing URI
    /// a new device scans. Unset, the server omits it and the app fills in the
    /// address it already had to know to get here.
    pub public_url: Option<String>,
    pub limits: Limits,
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

/// How hard a stranger is allowed to knock.
///
/// These bound the unauthenticated routes and the credential check. They are
/// not quotas on what a paired device may store; that is a separate control.
#[derive(Clone, Debug)]
pub struct Limits {
    /// Redemption attempts allowed per client, and separately per root.
    pub enroll_attempts_per_minute: u32,
    /// Roots one client may create per minute. Provisioning is open by default,
    /// so this is what stops an open server being turned into free storage.
    pub roots_per_minute: u32,
    /// Handle lookups allowed per client. This is the one route that confirms
    /// a root exists, so it is capped even though it reveals nothing else.
    pub handle_lookups_per_minute: u32,
    /// Consecutive failures a client may make before lockouts begin, so an
    /// ordinary mistyped code or stale token costs nothing.
    pub failures_before_backoff: u32,
    /// Longest a client can be locked out for. Each failure past the threshold
    /// doubles the wait up to this ceiling.
    pub max_backoff: Duration,
    /// Header naming the real client, for deployments behind a reverse proxy.
    ///
    /// Unset by default, and deliberately so: any client can send
    /// `X-Forwarded-For`, and honouring it unconditionally would let one host
    /// claim a fresh identity on every request and never be throttled. Set it
    /// only when a proxy you control is the sole way to reach this process.
    pub trusted_forwarded_header: Option<HeaderName>,
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

        let provisioning_secret = optional_from_env("GESH_PROVISIONING_SECRET");
        let public_url = optional_from_env("GESH_PUBLIC_URL");

        let limits = Limits {
            enroll_attempts_per_minute: count_from_env("GESH_ENROLL_ATTEMPTS_PER_MINUTE", 10)?,
            roots_per_minute: count_from_env("GESH_ROOTS_PER_MINUTE", 5)?,
            handle_lookups_per_minute: count_from_env("GESH_HANDLE_LOOKUPS_PER_MINUTE", 60)?,
            failures_before_backoff: count_from_env("GESH_FAILURES_BEFORE_BACKOFF", 5)?,
            max_backoff: duration_from_env("GESH_MAX_BACKOFF_SECONDS", 5 * 60)?,
            trusted_forwarded_header: forwarded_header_from_env("GESH_TRUSTED_FORWARDED_HEADER")?,
        };

        Ok(Self {
            listen_addr,
            blob_base_dir,
            secret_registry_path,
            database_options,
            upload_limit_bytes,
            retention,
            enrollment_code_ttl,
            provisioning_secret,
            public_url,
            limits,
        })
    }
}

fn optional_from_env(key: &'static str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn duration_from_env(key: &'static str, default_seconds: u64) -> Result<Duration> {
    let seconds = env::var(key)
        .unwrap_or_else(|_| default_seconds.to_string())
        .parse::<u64>()
        .with_context(|| format!("{key} must be a whole number of seconds"))?;

    Ok(Duration::from_secs(seconds))
}

fn count_from_env(key: &'static str, default: u32) -> Result<u32> {
    let count = env::var(key)
        .unwrap_or_else(|_| default.to_string())
        .parse::<u32>()
        .with_context(|| format!("{key} must be a whole number"))?;

    if count == 0 {
        anyhow::bail!("{key} must be greater than zero");
    }

    Ok(count)
}

fn forwarded_header_from_env(key: &'static str) -> Result<Option<HeaderName>> {
    let Ok(name) = env::var(key) else {
        return Ok(None);
    };

    if name.trim().is_empty() {
        return Ok(None);
    }

    HeaderName::try_from(name.trim().to_ascii_lowercase())
        .map(Some)
        .with_context(|| format!("{key} must be a valid HTTP header name"))
}
