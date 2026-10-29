// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-client-owner-binding-test-{nanos_chirho}-{n_chirho}"
    ))
}

fn principal_chirho(
    root_chirho: &Path,
    kind_chirho: identity_chirho::PrincipalKindChirho,
) -> String {
    identity_chirho::register_identity_chirho(root_chirho, kind_chirho)
        .unwrap()
        .principal_chirho
}

#[test]
fn client_owner_binding_mints_once_and_reuses_owner_chirho() {
    let root_chirho = tmp_root_chirho();
    let user_chirho = principal_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
    );

    let first_chirho =
        resolve_or_mint_client_owner_binding_chirho(&root_chirho, &user_chirho).unwrap();
    let second_chirho =
        resolve_or_mint_client_owner_binding_chirho(&root_chirho, &user_chirho).unwrap();

    assert_eq!(
        first_chirho.owner_principal_chirho,
        second_chirho.owner_principal_chirho
    );
    assert_eq!(
        verify_client_owner_bindings_chirho(&root_chirho).unwrap(),
        1
    );
    assert_eq!(
        active_client_owner_binding_for_user_chirho(&root_chirho, &user_chirho)
            .unwrap()
            .unwrap()
            .owner_principal_chirho,
        first_chirho.owner_principal_chirho
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn client_owner_binding_rejects_wrong_kinds_and_duplicate_active_rows_chirho() {
    let root_chirho = tmp_root_chirho();
    let user_chirho = principal_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
    );
    let owner_one_chirho = principal_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    );
    let owner_two_chirho = principal_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    );

    append_client_owner_binding_record_chirho(&root_chirho, &user_chirho, &owner_one_chirho)
        .unwrap();
    append_client_owner_binding_record_chirho(&root_chirho, &user_chirho, &owner_two_chirho)
        .unwrap();
    let duplicate_error_chirho = verify_client_owner_bindings_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(duplicate_error_chirho.contains("duplicate active client owner binding"));

    let wrong_kind_root_chirho = tmp_root_chirho();
    let owner_as_user_chirho = principal_chirho(
        &wrong_kind_root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    );
    let owner_chirho = principal_chirho(
        &wrong_kind_root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    );
    let kind_error_chirho = append_client_owner_binding_record_chirho(
        &wrong_kind_root_chirho,
        &owner_as_user_chirho,
        &owner_chirho,
    )
    .unwrap_err()
    .to_string();
    assert!(kind_error_chirho.contains("user_principal_chirho"));

    let _ = std::fs::remove_dir_all(&root_chirho);
    let _ = std::fs::remove_dir_all(&wrong_kind_root_chirho);
}
