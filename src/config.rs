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

        Ok(Self {
            listen_addr,
            blob_base_dir,
            secret_registry_path,
            database_options,
            upload_limit_bytes,
        })
    }
}
