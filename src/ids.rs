pub const MAX_ID_LEN: usize = 128;
pub const MIN_HANDLE_LEN: usize = 3;
pub const MAX_HANDLE_LEN: usize = 64;

pub fn is_valid_id(value: &str) -> bool {
    let len = value.len();
    len > 0
        && len <= MAX_ID_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// A root handle is the name a person types to find their sync root before
/// authenticating, so it is deliberately narrower than an identifier: lowercase
/// only, so that a handle cannot be confused with a differently cased one.
pub fn is_valid_handle(value: &str) -> bool {
    let len = value.len();
    (MIN_HANDLE_LEN..=MAX_HANDLE_LEN).contains(&len)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_expected_ids() {
        assert!(is_valid_id("fattern"));
        assert!(is_valid_id("root_7c5e1bb3-fca2-4e24-8c15-0fbb72e4f121"));
    }

    #[test]
    fn accepts_typable_handles() {
        assert!(is_valid_handle("madsen-home"));
        assert!(is_valid_handle("fattern2"));
    }

    #[test]
    fn rejects_ambiguous_or_unsafe_handles() {
        assert!(!is_valid_handle("Madsen-Home"));
        assert!(!is_valid_handle("has space"));
        assert!(!is_valid_handle("ab"));
        assert!(!is_valid_handle(&"a".repeat(MAX_HANDLE_LEN + 1)));
    }

    #[test]
    fn rejects_path_traversal_and_unsafe_characters() {
        assert!(!is_valid_id("../secrets"));
        assert!(!is_valid_id("device/name"));
        assert!(!is_valid_id(""));
        assert!(!is_valid_id(&"a".repeat(MAX_ID_LEN + 1)));
    }
}
