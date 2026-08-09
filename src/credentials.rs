//! Transport credentials: what a device presents to reach a sync root.
//!
//! These authorize traffic and nothing more. GESH never holds the key that
//! decrypts an event, so a credential minted here lets a device relay
//! ciphertext, not read it. Pairing a device therefore always has two halves:
//! the transport credential issued by the server, and the content key handed
//! over out of band by the device that already has it.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

/// Characters an enrollment code is drawn from, chosen so a code can be read
/// aloud or retyped without `0`/`O` and `1`/`I` ambiguity.
const CODE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
const CODE_GROUP: usize = 5;
const CODE_GROUPS: usize = 2;

/// A freshly minted device token, returned to the enrolling device exactly
/// once. Only [`Self::token_id`] and the hash of the secret are ever stored.
#[derive(Debug, Clone)]
pub struct DeviceToken {
    pub token_id: String,
    pub secret: String,
}

impl DeviceToken {
    pub fn mint() -> Self {
        Self {
            token_id: Uuid::new_v4().simple().to_string(),
            // Two v4 UUIDs give 244 bits from the platform CSPRNG.
            secret: format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()),
        }
    }

    /// The single string a device stores and presents as its bearer token.
    pub fn presentation(&self) -> String {
        format!("{}.{}", self.token_id, self.secret)
    }

    pub fn secret_hash(&self) -> Vec<u8> {
        hash(self.secret.as_bytes())
    }
}

/// Splits a presented bearer token into its lookup half and its secret half.
///
/// The token carries its own identifier so a credential can be found without
/// scanning every row, which is what allows the stored secret to be compared in
/// constant time against exactly one candidate.
pub fn split_token(presented: &str) -> Option<(&str, &str)> {
    let (token_id, secret) = presented.split_once('.')?;

    if token_id.is_empty() || secret.is_empty() {
        return None;
    }

    if !token_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }

    Some((token_id, secret))
}

/// A one-time code that lets a device join a root it has no credential for.
#[derive(Debug, Clone)]
pub struct EnrollmentCode {
    pub code: String,
}

impl EnrollmentCode {
    pub fn mint() -> Self {
        let bytes = Uuid::new_v4().into_bytes();
        let mut code = String::with_capacity(CODE_GROUPS * CODE_GROUP + CODE_GROUPS - 1);

        for group in 0..CODE_GROUPS {
            if group > 0 {
                code.push('-');
            }

            for index in 0..CODE_GROUP {
                let byte = bytes[group * CODE_GROUP + index];
                code.push(CODE_ALPHABET[usize::from(byte) % CODE_ALPHABET.len()] as char);
            }
        }

        Self { code }
    }

    pub fn hash(&self) -> Vec<u8> {
        hash_code(&self.code)
    }
}

/// Normalizes a typed code before hashing, so casing and the grouping dash do
/// not decide whether enrollment succeeds.
pub fn hash_code(code: &str) -> Vec<u8> {
    let normalized: String = code
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_uppercase())
        .collect();

    hash(normalized.as_bytes())
}

/// Device secrets are 244 bits of CSPRNG output rather than anything a person
/// chose, so a digest is the right comparison primitive here; the slow hashing
/// a password would need buys nothing against an input that cannot be guessed.
pub fn verify_secret(presented: &str, stored_hash: &[u8]) -> bool {
    let presented_hash = hash(presented.as_bytes());

    if presented_hash.len() != stored_hash.len() {
        return false;
    }

    bool::from(presented_hash.ct_eq(stored_hash))
}

fn hash(value: &[u8]) -> Vec<u8> {
    Sha256::digest(value).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_verifies_only_against_its_own_secret() {
        let token = DeviceToken::mint();
        let stored = token.secret_hash();

        assert!(verify_secret(&token.secret, &stored));
        assert!(!verify_secret("not-the-secret", &stored));
        assert!(!verify_secret(&DeviceToken::mint().secret, &stored));
    }

    #[test]
    fn a_presented_token_splits_into_lookup_and_secret() {
        let token = DeviceToken::mint();
        let presented = token.presentation();

        let (token_id, secret) = split_token(&presented).expect("token splits");
        assert_eq!(token_id, token.token_id);
        assert_eq!(secret, token.secret);

        assert!(split_token("no-separator").is_none());
        assert!(split_token(".secret").is_none());
        assert!(split_token("token.").is_none());
        assert!(split_token("nothex.secret").is_none());
    }

    #[test]
    fn codes_are_typable_and_normalize_before_hashing() {
        let code = EnrollmentCode::mint();

        assert_eq!(code.code.len(), CODE_GROUPS * CODE_GROUP + CODE_GROUPS - 1);
        assert!(
            code.code
                .chars()
                .all(|character| character == '-' || CODE_ALPHABET.contains(&(character as u8)))
        );

        let typed = code.code.to_ascii_lowercase().replace('-', "");
        assert_eq!(hash_code(&typed), code.hash());
        assert_ne!(hash_code("WRONG-CODE1"), code.hash());
    }
}
