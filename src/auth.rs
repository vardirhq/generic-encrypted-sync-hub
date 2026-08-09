use std::{collections::HashMap, path::Path};

use anyhow::{Context, Result};
use http::HeaderMap;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{
    credentials::{split_token, verify_secret},
    store::{CredentialRole, Store, StoreError},
};

pub type SecretRegistry = HashMap<String, HashMap<String, String>>;

/// Who a request is acting as on a root.
///
/// The distinction is a privilege boundary, not a label: a device credential
/// relays events for one device, while the root secret is the authority that
/// enrolls and revokes devices. A compromised phone therefore cannot enroll
/// another one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    Root,
    Device(String),
}

/// Loads the legacy secret registry, if there is one.
///
/// A registry is no longer how a root comes into existence — an app provisions
/// its own root and is handed its credentials — so a missing file is the normal
/// case and not an error. Deployments that already have one keep working.
pub async fn load_secret_registry(path: &Path) -> Result<SecretRegistry> {
    let raw = match tokio::fs::read_to_string(path).await {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(SecretRegistry::new());
        }
        Err(err) => {
            return Err(err)
                .with_context(|| format!("failed to read secret registry at {}", path.display()));
        }
    };

    serde_json::from_str(&raw).context("secret registry is not valid JSON")
}

/// Resolves the identity behind a bearer token for one `(appId, rootId)`.
///
/// Stored credentials are tried first: they are what provisioning and pairing
/// issue, and the only place a root's authority normally lives. The registry is
/// consulted afterwards so a deployment that predates self-provisioning keeps
/// working.
pub async fn authenticate(
    registry: &SecretRegistry,
    store: &Store,
    headers: &HeaderMap,
    app_id: &str,
    root_id: &str,
) -> Result<Option<Identity>, StoreError> {
    let Some(presented) = bearer_token(headers) else {
        return Ok(None);
    };

    if let Some((token_id, secret)) = split_token(presented)
        && let Some(credential) = store.credential(token_id).await?
        && credential.app_id == app_id
        && credential.root_id == root_id
        && verify_secret(secret, &credential.secret_hash)
    {
        return Ok(Some(match credential.role {
            CredentialRole::Root => Identity::Root,
            CredentialRole::Device => Identity::Device(credential.device_id),
        }));
    }

    if is_root_secret(registry, presented, app_id, root_id) {
        return Ok(Some(Identity::Root));
    }

    Ok(None)
}

/// Whether a request presents a bearer token matching `expected`.
///
/// Used for the server-wide provisioning secret, which is not tied to any root
/// and so cannot go through [`authenticate`].
pub fn presents_secret(headers: &HeaderMap, expected: &str) -> bool {
    let Some(presented) = bearer_token(headers) else {
        return false;
    };

    constant_time_secret_eq(Some(expected), presented)
}

fn is_root_secret(registry: &SecretRegistry, presented: &str, app_id: &str, root_id: &str) -> bool {
    let expected = registry
        .get(app_id)
        .and_then(|roots| roots.get(root_id))
        .map(String::as_str);

    constant_time_secret_eq(expected, presented)
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;

    // RFC 7235 makes the scheme case-insensitive; the credential is not.
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }

    Some(token).filter(|token| !token.is_empty())
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
    use http::header::AUTHORIZATION;

    use super::*;

    fn headers_with(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, value.parse().expect("header value"));
        headers
    }

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

    #[test]
    fn the_bearer_scheme_is_case_insensitive() {
        assert_eq!(bearer_token(&headers_with("Bearer token")), Some("token"));
        assert_eq!(bearer_token(&headers_with("bearer token")), Some("token"));
        assert_eq!(bearer_token(&headers_with("BEARER token")), Some("token"));
    }

    #[test]
    fn other_schemes_and_empty_credentials_are_refused() {
        assert_eq!(bearer_token(&headers_with("Basic token")), None);
        assert_eq!(bearer_token(&headers_with("Bearer ")), None);
        assert_eq!(bearer_token(&headers_with("token")), None);
    }
}
