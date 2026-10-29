// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)
//! Arms for the credential floor L.J. settled on 2026-10-04 (relayed in PFE #26041): 15 characters, counted as Unicode
//! code points after trim, at every road that chooses a credential, while an existing shorter password keeps signing in.
//!
//! The fixtures write L.J.'s numbers LITERALLY. An arm that derived them from `IDENTITY_CREDENTIAL_MIN_CHARS_CHIRHO`
//! would move with a wrong constant and stay green.
//! Migration paths: an arm that reds because the number moved is a retarget only with L.J.'s word. An arm that reds
//! because a road stopped calling the shared floor, or because sign-in or the legacy upgrade started asking it, is a
//! regression.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

const FOURTEEN_CHIRHO: &str = "fourteen-chars";
const FIFTEEN_CHIRHO: &str = "fifteen-chars-x";
const OTHER_FIFTEEN_CHIRHO: &str = "another-fifteen";
/// An 8-character password, as the old floor allowed.
const EIGHT_CHIRHO: &str = "eight-ch";

fn floor_tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-credential-floor-test-{n_chirho}-{}",
        now_ms_chirho()
    ))
}

fn signs_in_chirho(root_chirho: &Path, principal_chirho: &str, credential_chirho: &str) -> bool {
    login_identity_with_credential_chirho(root_chirho, principal_chirho, credential_chirho).is_ok()
}

#[test]
fn the_floor_is_fifteen_code_points_after_trim_never_bytes_chirho() {
    assert_eq!(
        [
            FOURTEEN_CHIRHO,
            FIFTEEN_CHIRHO,
            OTHER_FIFTEEN_CHIRHO,
            EIGHT_CHIRHO
        ]
        .map(|fixture_chirho| fixture_chirho.chars().count()),
        [14, 15, 15, 8],
        "the fixtures are the lengths their names say"
    );
    assert!(
        !credential_meets_floor_chirho(FOURTEEN_CHIRHO),
        "14 characters refuse"
    );
    assert!(
        credential_meets_floor_chirho(FIFTEEN_CHIRHO),
        "15 characters pass"
    );

    // Code points, never bytes: seven two-byte letters and one ASCII letter are 15 BYTES and 8 characters.
    let fifteen_bytes_chirho = format!("{}a", "\u{e9}".repeat(7));
    assert_eq!(
        (
            fifteen_bytes_chirho.len(),
            fifteen_bytes_chirho.chars().count()
        ),
        (15, 8)
    );
    assert!(
        !credential_meets_floor_chirho(&fifteen_bytes_chirho),
        "15 bytes that are 8 characters refuse"
    );
    assert!(
        !credential_meets_floor_chirho(&"\u{e9}".repeat(14)),
        "14 non-ASCII characters (28 bytes) refuse"
    );
    assert!(
        credential_meets_floor_chirho(&"\u{e9}".repeat(15)),
        "15 non-ASCII characters pass"
    );

    // After trim: whitespace around the password is not part of it.
    assert!(!credential_meets_floor_chirho(&format!(
        "  {FOURTEEN_CHIRHO}  "
    )));
    assert!(credential_meets_floor_chirho(&format!(
        " {FIFTEEN_CHIRHO} "
    )));

    // The unit is the code point, as NIST SP 800-63B-4 counts one: an accent written as a combining mark is its own
    // code point, so 8 such letters are 16 characters.
    assert!(credential_meets_floor_chirho(&"e\u{301}".repeat(8)));

    assert!(
        IDENTITY_CREDENTIAL_FLOOR_MESSAGE_CHIRHO.contains("at least 15 characters"),
        "the refusal states L.J.'s number: {IDENTITY_CREDENTIAL_FLOOR_MESSAGE_CHIRHO}"
    );
}

#[test]
fn every_road_that_chooses_a_credential_refuses_fourteen_and_accepts_fifteen_chirho() {
    let root_chirho = floor_tmp_root_chirho();

    // Registration with a credential: the operator's `identity-register --credential-file`, and the served
    // registration road, which checks the same floor before it calls this. Refused, nothing is registered.
    let error_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        FOURTEEN_CHIRHO,
    )
    .unwrap_err();
    assert!(error_chirho
        .to_string()
        .contains(IDENTITY_CREDENTIAL_FLOOR_MESSAGE_CHIRHO));
    assert!(
        load_verified_identities_chirho(&root_chirho)
            .unwrap_or_default()
            .is_empty(),
        "a refused registration registers no one"
    );
    let registered_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        FIFTEEN_CHIRHO,
    )
    .unwrap()
    .principal_chirho;
    assert!(signs_in_chirho(
        &root_chirho,
        &registered_chirho,
        FIFTEEN_CHIRHO
    ));

    // The operator set, on a credentialless principal: refused, no credential is written.
    let bare_chirho = register_identity_chirho(&root_chirho, PrincipalKindChirho::UserChirho)
        .unwrap()
        .principal_chirho;
    let error_chirho =
        set_identity_credential_chirho(&root_chirho, &bare_chirho, FOURTEEN_CHIRHO).unwrap_err();
    assert!(error_chirho
        .to_string()
        .contains(IDENTITY_CREDENTIAL_FLOOR_MESSAGE_CHIRHO));
    assert!(
        load_identity_key_record_chirho(&root_chirho, &bare_chirho)
            .unwrap()
            .credential_hash_chirho
            .is_none(),
        "a refused set writes no credential"
    );
    set_identity_credential_chirho(&root_chirho, &bare_chirho, FIFTEEN_CHIRHO).unwrap();
    assert!(signs_in_chirho(&root_chirho, &bare_chirho, FIFTEEN_CHIRHO));

    // The operator reset: refused by its own identity, and the old credential still signs in.
    let error_chirho = reset_identity_credential_chirho(
        &root_chirho,
        &registered_chirho,
        FOURTEEN_CHIRHO,
        "operator-cli-chirho",
        "operator-reset-chirho",
    )
    .unwrap_err();
    assert_eq!(
        error_chirho.downcast_ref::<IdentityCredentialResetRefusalChirho>(),
        Some(&IdentityCredentialResetRefusalChirho::CredentialBelowFloorChirho)
    );
    assert!(signs_in_chirho(
        &root_chirho,
        &registered_chirho,
        FIFTEEN_CHIRHO
    ));
    reset_identity_credential_chirho(
        &root_chirho,
        &registered_chirho,
        OTHER_FIFTEEN_CHIRHO,
        "operator-cli-chirho",
        "operator-reset-chirho",
    )
    .unwrap();
    assert!(signs_in_chirho(
        &root_chirho,
        &registered_chirho,
        OTHER_FIFTEEN_CHIRHO
    ));

    // R1's self-service change, behind her own session: refused by its token, then accepted.
    let token_chirho =
        login_identity_with_credential_chirho(&root_chirho, &bare_chirho, FIFTEEN_CHIRHO)
            .unwrap()
            .token_chirho;
    let error_chirho = change_identity_credential_for_session_chirho(
        &root_chirho,
        &bare_chirho,
        &token_chirho,
        FIFTEEN_CHIRHO,
        FOURTEEN_CHIRHO,
    )
    .unwrap_err();
    assert_eq!(
        credential_change_refusal_token_chirho(&error_chirho),
        Some("credential-too-weak-chirho")
    );
    assert!(signs_in_chirho(&root_chirho, &bare_chirho, FIFTEEN_CHIRHO));
    change_identity_credential_for_session_chirho(
        &root_chirho,
        &bare_chirho,
        &token_chirho,
        FIFTEEN_CHIRHO,
        OTHER_FIFTEEN_CHIRHO,
    )
    .unwrap();
    assert!(signs_in_chirho(
        &root_chirho,
        &bare_chirho,
        OTHER_FIFTEEN_CHIRHO
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn an_existing_shorter_password_keeps_signing_in_and_only_a_new_one_meets_the_floor_chirho() {
    let root_chirho = floor_tmp_root_chirho();
    let principal_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        FIFTEEN_CHIRHO,
    )
    .unwrap()
    .principal_chirho;

    // An 8-character password set under the old floor, stored as the old code stored it: an Argon2id hash.
    let mut key_record_chirho =
        load_identity_key_record_chirho(&root_chirho, &principal_chirho).unwrap();
    let salt_chirho = random_salt_chirho();
    key_record_chirho.credential_hash_chirho =
        Some(credential_hash_chirho(&salt_chirho, EIGHT_CHIRHO).unwrap());
    key_record_chirho.credential_salt_chirho = Some(salt_chirho);
    write_identity_key_record_chirho(&root_chirho, &key_record_chirho).unwrap();
    assert!(
        signs_in_chirho(&root_chirho, &principal_chirho, EIGHT_CHIRHO),
        "an existing 8-character password signs in: sign-in never asks the floor"
    );

    // The same password under the legacy hash signs in and is upgraded. The upgrade is not a new credential, so the
    // floor is not asked there either.
    let mut key_record_chirho =
        load_identity_key_record_chirho(&root_chirho, &principal_chirho).unwrap();
    let legacy_salt_chirho = key_record_chirho.credential_salt_chirho.clone().unwrap();
    key_record_chirho.credential_hash_chirho = Some(legacy_credential_hash_blake3_chirho(
        &legacy_salt_chirho,
        EIGHT_CHIRHO,
    ));
    write_identity_key_record_chirho(&root_chirho, &key_record_chirho).unwrap();
    assert!(signs_in_chirho(
        &root_chirho,
        &principal_chirho,
        EIGHT_CHIRHO
    ));
    assert!(
        load_identity_key_record_chirho(&root_chirho, &principal_chirho)
            .unwrap()
            .credential_hash_chirho
            .unwrap()
            .starts_with(CREDENTIAL_HASH_ARGON2ID_V1_CHIRHO),
        "the legacy hash was upgraded"
    );

    // Her change proves the CURRENT 8-character password; the floor judges only the NEW one.
    let token_chirho =
        login_identity_with_credential_chirho(&root_chirho, &principal_chirho, EIGHT_CHIRHO)
            .unwrap()
            .token_chirho;
    let error_chirho = change_identity_credential_for_session_chirho(
        &root_chirho,
        &principal_chirho,
        &token_chirho,
        EIGHT_CHIRHO,
        "eight-c2",
    )
    .unwrap_err();
    assert_eq!(
        credential_change_refusal_token_chirho(&error_chirho),
        Some("credential-too-weak-chirho"),
        "a new 8-character password is refused"
    );
    change_identity_credential_for_session_chirho(
        &root_chirho,
        &principal_chirho,
        &token_chirho,
        EIGHT_CHIRHO,
        OTHER_FIFTEEN_CHIRHO,
    )
    .unwrap();
    assert!(signs_in_chirho(
        &root_chirho,
        &principal_chirho,
        OTHER_FIFTEEN_CHIRHO
    ));
    assert!(!signs_in_chirho(
        &root_chirho,
        &principal_chirho,
        EIGHT_CHIRHO
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
}
