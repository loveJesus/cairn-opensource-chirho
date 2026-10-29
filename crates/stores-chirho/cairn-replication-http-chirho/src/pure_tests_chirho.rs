// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Unit tests for the security-relevant pure validators: object-hash shape (rejects wrong length,
//! uppercase, and non-hex so a route param can never be a path or key) and the constant-time bearer
//! comparison, plus the URL builders the client uses.

use crate::{
    bearer_header_matches_chirho, constant_time_eq_chirho, is_valid_object_hash_chirho,
    log_by_name_url_chirho, object_by_hash_url_chirho, objects_list_url_chirho,
};

#[test]
fn object_hash_validation_is_strict_chirho() {
    // Exactly 64 lowercase hex passes.
    assert!(is_valid_object_hash_chirho(&"a".repeat(64)));
    assert!(is_valid_object_hash_chirho(&"0123456789abcdef".repeat(4)));
    // Wrong length fails (too short and too long).
    assert!(!is_valid_object_hash_chirho(&"a".repeat(63)));
    assert!(!is_valid_object_hash_chirho(&"a".repeat(65)));
    assert!(!is_valid_object_hash_chirho(""));
    // Uppercase hex fails — content addresses are lowercase.
    assert!(!is_valid_object_hash_chirho(&"A".repeat(64)));
    // Non-hex characters fail (a path separator, a dot, a `g`).
    assert!(!is_valid_object_hash_chirho(&format!(
        "{}/",
        "a".repeat(63)
    )));
    assert!(!is_valid_object_hash_chirho(&format!(
        "{}.",
        "a".repeat(63)
    )));
    assert!(!is_valid_object_hash_chirho(&"g".repeat(64)));
}

#[test]
fn constant_time_eq_matches_semantics_chirho() {
    assert!(constant_time_eq_chirho(
        b"same-token-chirho",
        b"same-token-chirho"
    ));
    assert!(!constant_time_eq_chirho(
        b"token-a-chirho",
        b"token-b-chirho"
    ));
    // Different lengths are unequal.
    assert!(!constant_time_eq_chirho(b"short", b"longer-token"));
    assert!(constant_time_eq_chirho(b"", b""));
}

#[test]
fn bearer_header_requires_the_exact_scheme_and_value_chirho() {
    assert!(bearer_header_matches_chirho(
        "secret-chirho",
        Some("Bearer secret-chirho")
    ));
    assert!(!bearer_header_matches_chirho(
        "secret-chirho",
        Some("bearer secret-chirho")
    ));
    assert!(!bearer_header_matches_chirho(
        "secret-chirho",
        Some("Bearer wrong-chirho")
    ));
    assert!(!bearer_header_matches_chirho("secret-chirho", None));
}

#[test]
fn url_builders_join_without_double_slashes_chirho() {
    assert_eq!(
        objects_list_url_chirho("http://127.0.0.1:8080"),
        "http://127.0.0.1:8080/replication-chirho/objects-chirho"
    );
    // A trailing slash on the base is trimmed, never doubled.
    assert_eq!(
        objects_list_url_chirho("http://127.0.0.1:8080/"),
        "http://127.0.0.1:8080/replication-chirho/objects-chirho"
    );
    assert_eq!(
        object_by_hash_url_chirho("http://host", &"a".repeat(64)),
        format!(
            "http://host/replication-chirho/objects-chirho/{}",
            "a".repeat(64)
        )
    );
    assert_eq!(
        log_by_name_url_chirho("http://host", "gate1-log-anchors-chirho.jsonl"),
        "http://host/replication-chirho/logs-chirho/gate1-log-anchors-chirho.jsonl"
    );
}
