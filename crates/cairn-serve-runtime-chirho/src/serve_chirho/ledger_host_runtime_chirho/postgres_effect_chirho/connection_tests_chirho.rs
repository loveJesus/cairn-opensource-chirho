// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use cairn_secret_chirho::secret_chirho::set_secret_chirho;
use std::sync::atomic::{AtomicU64, Ordering};

#[test]
fn local_phase_b_connection_refusal_is_fixed_redacted_and_write_free_chirho() {
    static NEXT_ROOT_CHIRHO: AtomicU64 = AtomicU64::new(1);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-local-phase-b-connection-{}-chirho",
        NEXT_ROOT_CHIRHO.fetch_add(1, Ordering::Relaxed)
    ));
    let secret_name_chirho = "cf7-postgres-connection-chirho";
    let secret_value_chirho =
        b"host=127.0.0.1 port=1 user=local-user-chirho password=private-dsn-fragment-chirho";
    set_secret_chirho(&root_chirho, secret_name_chirho, secret_value_chirho).unwrap();
    let secret_path_chirho = root_chirho
        .join("private-secrets-chirho")
        .join(format!("{secret_name_chirho}.secret-chirho"));
    let before_chirho = std::fs::read(&secret_path_chirho).unwrap();

    let error_chirho = connect_local_phase_b_database_chirho(&root_chirho, secret_name_chirho)
        .err()
        .expect("the malformed private DSN must refuse through the fixed host error");

    assert_eq!(
        error_chirho.downcast_ref::<LedgerHostPostgresEffectRefusalChirho>(),
        Some(&LedgerHostPostgresEffectRefusalChirho::ConnectionUnavailableChirho)
    );
    let display_chirho = error_chirho.to_string();
    assert!(!display_chirho.contains(secret_name_chirho));
    assert!(!display_chirho.contains("private-dsn-fragment-chirho"));
    assert_eq!(std::fs::read(&secret_path_chirho).unwrap(), before_chirho);
    assert_eq!(
        std::fs::read_dir(root_chirho.join("private-secrets-chirho"))
            .unwrap()
            .count(),
        1,
        "a refused connection preflight must not create provider or evidence state"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn local_phase_b_connection_parser_refuses_nonloopback_endpoints_chirho() {
    let remote_chirho = "host=203.0.113.8 user=private-user-chirho password=private-value-chirho";
    let error_chirho = parse_local_phase_b_connection_config_chirho(remote_chirho).unwrap_err();
    assert_eq!(
        error_chirho.downcast_ref::<LedgerHostPostgresEffectRefusalChirho>(),
        Some(&LedgerHostPostgresEffectRefusalChirho::ConnectionOutsideLocalPhaseBChirho)
    );
    assert!(!error_chirho.to_string().contains("203.0.113.8"));
    assert!(!error_chirho.to_string().contains("private-value-chirho"));

    assert!(
        parse_local_phase_b_connection_config_chirho("host=127.0.0.1 user=local-user-chirho")
            .is_ok()
    );
    assert!(
        parse_local_phase_b_connection_config_chirho("host=::1 user=local-user-chirho").is_ok()
    );
}
