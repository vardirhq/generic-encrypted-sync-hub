pub const MAX_ID_LEN: usize = 128;

pub fn is_valid_id(value: &str) -> bool {
    let len = value.len();
    len > 0
        && len <= MAX_ID_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
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
    fn rejects_path_traversal_and_unsafe_characters() {
        assert!(!is_valid_id("../secrets"));
        assert!(!is_valid_id("device/name"));
        assert!(!is_valid_id(""));
        assert!(!is_valid_id(&"a".repeat(MAX_ID_LEN + 1)));
    }
}
