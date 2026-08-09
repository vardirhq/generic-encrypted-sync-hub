use std::{collections::HashMap, path::Path};

use anyhow::{Context, Result};
use http::HeaderMap;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub type SecretRegistry = HashMap<String, HashMap<String, String>>;

pub async fn load_secret_registry(path: &Path) -> Result<SecretRegistry> {
    let raw = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read secret registry at {}", path.display()))?;

    serde_json::from_str(&raw).context("secret registry is not valid JSON")
}

pub fn is_authorized(
    registry: &SecretRegistry,
    headers: &HeaderMap,
    app_id: &str,
    root_id: &str,
) -> bool {
    let Some(presented) = bearer_token(headers) else {
        return false;
    };

    let expected = registry
        .get(app_id)
        .and_then(|roots| roots.get(root_id))
        .map(String::as_str);

    constant_time_secret_eq(expected, presented)
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
    value
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
}

fn constant_time_secret_eq(expected: Option<&str>, presented: &str) -> bool {
    let expected_hash: [u8; 32] = expected.map(hash_secret).unwrap_or([0_u8; 32]);
    let presented_hash = hash_secret(presented);
    let matches = expected_hash.ct_eq(&presented_hash);

    bool::from(matches) && expected.is_some()
}

fn hash_secret(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_comparison_accepts_only_exact_match() {
        assert!(constant_time_secret_eq(
            Some("correct horse"),
            "correct horse"
        ));
        assert!(!constant_time_secret_eq(
            Some("correct horse"),
            "wrong horse"
        ));
        assert!(!constant_time_secret_eq(None, "anything"));
    }
}
