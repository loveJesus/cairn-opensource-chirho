// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Brick 4b-2's arms: an owner's keys are named by an opaque id, listed for their owner alone, revoked by that id with
//! one refusal for every id that is not the viewer's own, and the issuance cap counts only live keys.

use super::*;
use identity_chirho::PrincipalKindChirho;
use std::sync::atomic::AtomicU64;

const APP_CHIRHO: &str = "alpha";
const SECRET_CHIRHO: &str = "key-listing-secret-chirho";
const NEW_SECRET_CHIRHO: &str = "key-listing-new-secret-chirho";

fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho = COUNTER_CHIRHO.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-key-listing-{label_chirho}-{}-{n_chirho}-{}",
        std::process::id(),
        now_ms_chirho()
    ));
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

struct FixtureChirho {
    root_chirho: PathBuf,
    client_chirho: OauthClientRecordChirho,
}

fn fixture_chirho(label_chirho: &str) -> FixtureChirho {
    let root_chirho = tmp_root_chirho(label_chirho);
    let owner_chirho =
        identity_chirho::register_identity_chirho(&root_chirho, PrincipalKindChirho::OwnerChirho)
            .unwrap();
    let client_chirho =
        register_client_chirho(&root_chirho, APP_CHIRHO, &owner_chirho.principal_chirho).unwrap();
    FixtureChirho {
        root_chirho,
        client_chirho,
    }
}

fn user_chirho(fixture_chirho: &FixtureChirho) -> String {
    identity_chirho::register_identity_chirho(
        &fixture_chirho.root_chirho,
        PrincipalKindChirho::UserChirho,
    )
    .unwrap()
    .principal_chirho
}

fn policy_chirho() -> ScopedTokenRateLimitChirho {
    ScopedTokenRateLimitChirho {
        window_ms_chirho: 60_000,
        max_invokes_chirho: 50,
        device_id_chirho: None,
    }
}

/// A key for `principal_chirho` from a fresh operator sign-in, with or without a policy.
fn key_chirho(
    fixture_chirho: &FixtureChirho,
    principal_chirho: &str,
    policy_chirho: Option<ScopedTokenRateLimitChirho>,
) -> ScopedTokenIssueChirho {
    let login_chirho =
        identity_chirho::login_identity_chirho(&fixture_chirho.root_chirho, principal_chirho)
            .unwrap();
    issue_scoped_token_after_login_chirho(
        &fixture_chirho.root_chirho,
        fixture_chirho.client_chirho.clone(),
        login_chirho,
        vec!["invoke_chirho".to_string()],
        policy_chirho,
    )
    .unwrap()
}

fn bearer_chirho(
    fixture_chirho: &FixtureChirho,
    token_chirho: &str,
) -> Option<ScopedTokenRecordChirho> {
    validate_scoped_token_for_app_chirho(&fixture_chirho.root_chirho, APP_CHIRHO, token_chirho)
        .unwrap()
}

fn revocations_chirho(fixture_chirho: &FixtureChirho) -> usize {
    identity_chirho::load_session_revocations_chirho(&fixture_chirho.root_chirho)
        .unwrap()
        .len()
}

fn key_id_of_chirho(issue_chirho: &ScopedTokenIssueChirho) -> String {
    scoped_key_id_chirho(&issue_chirho.record_chirho.token_hash_chirho)
}

/// THE KEY ID: 32 lowercase hex characters, stable, one per key, and never the token hash, a prefix of it, its plain
/// blake3, or the token's seq.
///
/// MIGRATION PATH: an id equal to the hash or its plain blake3 means the domain separation is gone; a short or shared
/// id means two keys could answer to one name.
#[test]
fn the_key_id_is_opaque_stable_and_one_per_key_chirho() {
    let fixture_chirho = fixture_chirho("key-id");
    let alice_chirho = user_chirho(&fixture_chirho);
    let first_chirho = key_chirho(&fixture_chirho, &alice_chirho, None);
    let second_chirho = key_chirho(&fixture_chirho, &alice_chirho, None);
    let id_chirho = key_id_of_chirho(&first_chirho);
    assert_eq!(id_chirho.len(), 32);
    assert!(id_chirho
        .chars()
        .all(|c_chirho| c_chirho.is_ascii_hexdigit() && !c_chirho.is_ascii_uppercase()));
    assert_eq!(id_chirho, key_id_of_chirho(&first_chirho), "stable");
    assert_ne!(id_chirho, key_id_of_chirho(&second_chirho), "one per key");
    let token_hash_chirho = &first_chirho.record_chirho.token_hash_chirho;
    assert!(
        !token_hash_chirho.contains(&id_chirho),
        "not a slice of the token hash"
    );
    assert!(
        !blake3::hash(token_hash_chirho.as_bytes())
            .to_hex()
            .contains(id_chirho.as_str()),
        "not the plain blake3 of the token hash: its own domain"
    );
    assert_ne!(id_chirho, first_chirho.record_chirho.seq_chirho.to_string());
}

/// THE LIST IS THE OWNER'S ALONE. Each owner sees exactly their own unexpired keys, oldest first. A key whose session
/// was revoked stays listed, marked not live, until it expires; an expired key is not listed. No row carries the key,
/// its token hash, or a seq.
///
/// MIGRATION PATH: another owner's key in a list is a cross-principal disclosure; a key or hash in a row is a leak.
#[test]
fn each_owner_lists_only_their_own_unexpired_keys_chirho() {
    let fixture_chirho = fixture_chirho("list");
    let alice_chirho = user_chirho(&fixture_chirho);
    let bob_chirho = user_chirho(&fixture_chirho);
    let alices_chirho = [
        key_chirho(&fixture_chirho, &alice_chirho, Some(policy_chirho())),
        key_chirho(&fixture_chirho, &alice_chirho, None),
    ];
    let bobs_chirho = key_chirho(&fixture_chirho, &bob_chirho, Some(policy_chirho()));
    let root_chirho = &fixture_chirho.root_chirho;
    let alice_rows_chirho = list_own_keys_chirho(root_chirho, &alice_chirho).unwrap();
    assert_eq!(
        alice_rows_chirho
            .iter()
            .map(|row_chirho| row_chirho.key_id_chirho.clone())
            .collect::<Vec<_>>(),
        alices_chirho
            .iter()
            .map(key_id_of_chirho)
            .collect::<Vec<_>>(),
        "alice sees her two keys, oldest first"
    );
    assert!(alice_rows_chirho
        .iter()
        .all(|row_chirho| row_chirho.live_chirho));
    assert_eq!(
        alice_rows_chirho[0].rate_limit_chirho,
        Some(policy_chirho())
    );
    assert_eq!(alice_rows_chirho[1].rate_limit_chirho, None);
    let bob_rows_chirho = list_own_keys_chirho(root_chirho, &bob_chirho).unwrap();
    assert_eq!(bob_rows_chirho.len(), 1);
    assert_eq!(
        bob_rows_chirho[0].key_id_chirho,
        key_id_of_chirho(&bobs_chirho)
    );
    let rendered_chirho = serde_json::to_string(&alice_rows_chirho).unwrap();
    for issue_chirho in &alices_chirho {
        assert!(
            !rendered_chirho.contains(&issue_chirho.token_chirho),
            "never the key"
        );
        assert!(
            !rendered_chirho.contains(&issue_chirho.record_chirho.token_hash_chirho),
            "never its hash"
        );
    }
    assert!(!rendered_chirho.contains("seq"), "never a seq");
    identity_chirho::revoke_session_by_seq_chirho(
        root_chirho,
        &alice_chirho,
        alices_chirho[0].record_chirho.session_seq_chirho,
        "operator-chirho",
        "list arm",
    )
    .unwrap();
    let after_chirho = list_own_keys_chirho(root_chirho, &alice_chirho).unwrap();
    assert_eq!(
        after_chirho.len(),
        2,
        "an ended key stays listed until it expires"
    );
    assert!(!after_chirho[0].live_chirho && after_chirho[1].live_chirho);
    let expiry_chirho = alices_chirho[1].record_chirho.expires_ms_chirho;
    assert!(
        key_listing_chirho::list_own_keys_at_chirho(root_chirho, &alice_chirho, expiry_chirho + 1)
            .unwrap()
            .is_empty(),
        "an expired key is not listed"
    );
}

/// REVOKE BY ID. The owner revokes a key by its id: the key then refuses on the bearer road, one revocation record is
/// appended, and the list marks it not live. A repeat answers the same success and appends nothing. Another key of
/// the same owner keeps working.
///
/// MIGRATION PATH: a second record for one revoke means the door's existing-record answer is gone; the revoked key
/// answering means the revoke reached the wrong session.
#[test]
fn a_key_revoked_by_its_id_refuses_and_a_repeat_appends_nothing_chirho() {
    let fixture_chirho = fixture_chirho("revoke");
    let alice_chirho = user_chirho(&fixture_chirho);
    let doomed_chirho = key_chirho(&fixture_chirho, &alice_chirho, Some(policy_chirho()));
    let kept_chirho = key_chirho(&fixture_chirho, &alice_chirho, Some(policy_chirho()));
    let root_chirho = &fixture_chirho.root_chirho;
    let before_chirho = revocations_chirho(&fixture_chirho);
    revoke_own_key_chirho(
        root_chirho,
        &alice_chirho,
        &key_id_of_chirho(&doomed_chirho),
    )
    .unwrap();
    assert_eq!(
        bearer_chirho(&fixture_chirho, &doomed_chirho.token_chirho),
        None,
        "the revoked key refuses"
    );
    assert_eq!(
        revocations_chirho(&fixture_chirho),
        before_chirho + 1,
        "one record"
    );
    revoke_own_key_chirho(
        root_chirho,
        &alice_chirho,
        &key_id_of_chirho(&doomed_chirho),
    )
    .expect("a repeat answers the same success");
    assert_eq!(
        revocations_chirho(&fixture_chirho),
        before_chirho + 1,
        "and appends nothing"
    );
    assert_eq!(
        bearer_chirho(&fixture_chirho, &kept_chirho.token_chirho),
        Some(kept_chirho.record_chirho.clone()),
        "the owner's other key keeps working"
    );
    let rows_chirho = list_own_keys_chirho(root_chirho, &alice_chirho).unwrap();
    assert!(!rows_chirho[0].live_chirho && rows_chirho[1].live_chirho);
}

/// ONE REFUSAL FOR EVERY ID THAT IS NOT THE VIEWER'S OWN. Bob naming Alice's key id, a malformed id, an id that never
/// existed and Alice's own EXPIRED key's id all refuse with the same error and append nothing; Alice's key keeps
/// working. The door looks only among the viewer's own unexpired keys, so another principal's id cannot be told from
/// an unknown one.
///
/// MIGRATION PATH: a different refusal for another owner's id is an existence oracle; Alice's key ending is a
/// cross-principal revoke.
#[test]
fn another_owners_key_id_refuses_exactly_as_an_unknown_one_chirho() {
    let fixture_chirho = fixture_chirho("cross");
    let alice_chirho = user_chirho(&fixture_chirho);
    let bob_chirho = user_chirho(&fixture_chirho);
    let alices_chirho = key_chirho(&fixture_chirho, &alice_chirho, Some(policy_chirho()));
    key_chirho(&fixture_chirho, &bob_chirho, Some(policy_chirho()));
    let root_chirho = &fixture_chirho.root_chirho;
    let before_chirho = revocations_chirho(&fixture_chirho);
    let refusal_chirho = |result_chirho: Result<()>| {
        let error_chirho = result_chirho.unwrap_err();
        assert!(
            error_chirho
                .downcast_ref::<UnknownScopedKeyChirho>()
                .is_some(),
            "{error_chirho:#}"
        );
        format!("{error_chirho:#}")
    };
    let alices_id_chirho = key_id_of_chirho(&alices_chirho);
    let cross_chirho = refusal_chirho(revoke_own_key_chirho(
        root_chirho,
        &bob_chirho,
        &alices_id_chirho,
    ));
    let unknown_chirho = refusal_chirho(revoke_own_key_chirho(
        root_chirho,
        &bob_chirho,
        &"0".repeat(32),
    ));
    let malformed_chirho = refusal_chirho(revoke_own_key_chirho(root_chirho, &bob_chirho, "zz"));
    let expired_chirho = refusal_chirho(key_listing_chirho::revoke_own_key_at_chirho(
        root_chirho,
        &alice_chirho,
        &alices_id_chirho,
        alices_chirho.record_chirho.expires_ms_chirho + 1,
    ));
    assert_eq!(
        cross_chirho, unknown_chirho,
        "another owner's id reads as an unknown one"
    );
    assert_eq!(malformed_chirho, unknown_chirho);
    assert_eq!(expired_chirho, unknown_chirho);
    assert_eq!(
        revocations_chirho(&fixture_chirho),
        before_chirho,
        "no refusal appends"
    );
    assert_eq!(
        bearer_chirho(&fixture_chirho, &alices_chirho.token_chirho),
        Some(alices_chirho.record_chirho.clone()),
        "Alice's key keeps working"
    );
}

/// THE CAP COUNTS LIVE KEYS (PFE #26022, item 5). At the cap a sixth rate-limited key is refused; revoking one key by
/// its id lets a new key issue at once; and after a credential reset at the cap, issuance with the new credential
/// proceeds, because every old key's session ended.
///
/// MIGRATION PATH: a refusal after the revoke or the reset means ended keys still hold their slots, so an owner at the
/// cap could not replace a key for a day.
#[test]
fn revoking_or_resetting_at_the_cap_frees_slots_at_once_chirho() {
    let fixture_chirho = fixture_chirho("cap");
    let root_chirho = &fixture_chirho.root_chirho;
    let alice_chirho = identity_chirho::register_identity_with_credential_chirho(
        root_chirho,
        PrincipalKindChirho::UserChirho,
        SECRET_CHIRHO,
    )
    .unwrap()
    .principal_chirho;
    let issue_chirho = |secret_chirho: &str| {
        issue_scoped_token_with_rate_limit_chirho(
            root_chirho,
            &alice_chirho,
            secret_chirho,
            &fixture_chirho.client_chirho.client_id_chirho,
            vec!["invoke_chirho".to_string()],
            Some(policy_chirho()),
        )
    };
    let keys_chirho: Vec<ScopedTokenIssueChirho> = (0
        ..LIVE_RATE_LIMITED_TOKENS_PER_PRINCIPAL_CHIRHO)
        .map(|_| issue_chirho(SECRET_CHIRHO).unwrap())
        .collect();
    let refusal_chirho = issue_chirho(SECRET_CHIRHO).unwrap_err();
    assert!(
        refusal_chirho
            .downcast_ref::<ScopedTokenCapReachedChirho>()
            .is_some(),
        "the control: at the cap a sixth key is refused: {refusal_chirho:#}"
    );
    revoke_own_key_chirho(
        root_chirho,
        &alice_chirho,
        &key_id_of_chirho(&keys_chirho[0]),
    )
    .unwrap();
    issue_chirho(SECRET_CHIRHO).expect("revoking a key frees its slot at once");
    assert!(
        issue_chirho(SECRET_CHIRHO)
            .unwrap_err()
            .downcast_ref::<ScopedTokenCapReachedChirho>()
            .is_some(),
        "and only that one slot"
    );
    identity_chirho::reset_identity_credential_chirho(
        root_chirho,
        &alice_chirho,
        NEW_SECRET_CHIRHO,
        "operator-chirho",
        "cap arm",
    )
    .unwrap();
    let fresh_chirho =
        issue_chirho(NEW_SECRET_CHIRHO).expect("a reset at the cap lets issuance proceed");
    assert_eq!(
        bearer_chirho(&fixture_chirho, &fresh_chirho.token_chirho),
        Some(fresh_chirho.record_chirho.clone())
    );
}
