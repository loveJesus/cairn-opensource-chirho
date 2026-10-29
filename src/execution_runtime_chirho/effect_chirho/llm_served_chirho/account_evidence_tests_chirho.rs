// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! gpt #28880's two-account same-content arm for served-LLM evidence: one content ref, two accounts, two keys; a frozen account's replay refuses and an erased account's evidence is gone, while the other account still reads.

use super::account_evidence_chirho::AccountEvidenceChirho;
use crate::model_chirho::RequestContextChirho;
use crate::privacy_chirho::PrivateBlobRefChirho;
use cairn_account_attribution_chirho::{
    freeze_account_unlocked_chirho, with_account_attribution_lock_chirho,
    AccountAttributionErrorChirho, AccountAttributionRefusalChirho, AccountCoordinateChirho,
};
use std::path::{Path, PathBuf};

/// A fresh, empty root for one test; the root crate carries no temp-dir crate for its tests.
fn fresh_root_chirho(label_chirho: &str) -> std::path::PathBuf {
    static COUNTER_CHIRHO: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n_chirho = COUNTER_CHIRHO.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-{label_chirho}-{}-{n_chirho}-chirho",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

fn context_chirho(user_chirho: &str) -> RequestContextChirho {
    RequestContextChirho {
        user_principal_chirho: user_chirho.to_owned(),
        app_chirho: "llm-evidence-app-chirho".to_owned(),
        owner_principal_chirho: "owner/llm-evidence-chirho".to_owned(),
        client_id_chirho: "client-chirho".to_owned(),
        token_hash_chirho: "0".repeat(64),
        price_book_chirho: None,
        billing_policy_chirho: None,
        key_limit_chirho: None,
    }
}

fn request_chirho(
    root_chirho: &Path,
    user_chirho: &str,
    bytes_chirho: &[u8],
) -> anyhow::Result<(Vec<u8>, PathBuf, String)> {
    let evidence_chirho =
        AccountEvidenceChirho::for_request_chirho(root_chirho, &context_chirho(user_chirho))?;
    let ref_chirho = blake3::hash(bytes_chirho).to_hex().to_string();
    let path_chirho = evidence_chirho.index_path_chirho("requests-chirho", &ref_chirho)?;
    let loaded_chirho = evidence_chirho.create_or_load_chirho(
        &path_chirho,
        "request",
        &ref_chirho,
        bytes_chirho,
        "served LLM request evidence",
    )?;
    Ok((
        loaded_chirho,
        path_chirho,
        evidence_chirho.subject_chirho("request", &ref_chirho),
    ))
}

fn key_id_chirho(index_path_chirho: &Path) -> String {
    let blob_chirho: PrivateBlobRefChirho =
        serde_json::from_slice(&std::fs::read(index_path_chirho).unwrap()).unwrap();
    blob_chirho.key_id_chirho
}

#[test]
fn two_accounts_with_the_same_prompt_hold_separate_keys_and_close_separately_chirho() {
    let root_chirho = fresh_root_chirho("llm-evidence");
    let root_path_chirho = root_chirho.as_path();
    let prompt_chirho = b"the same prompt, sent by two people";
    let (a_bytes_chirho, a_path_chirho, a_subject_chirho) =
        request_chirho(root_path_chirho, "user/a", prompt_chirho).unwrap();
    let (b_bytes_chirho, b_path_chirho, b_subject_chirho) =
        request_chirho(root_path_chirho, "user/b", prompt_chirho).unwrap();
    assert_eq!(a_bytes_chirho, prompt_chirho);
    assert_eq!(b_bytes_chirho, prompt_chirho);
    assert_ne!(
        a_subject_chirho, b_subject_chirho,
        "two accounts share one subject"
    );
    assert_ne!(a_path_chirho, b_path_chirho, "two accounts share one index");
    assert_ne!(
        key_id_chirho(&a_path_chirho),
        key_id_chirho(&b_path_chirho),
        "two accounts share one key"
    );

    // A closes: its replay refuses inside the lock, and A cannot mint a fresh key either.
    with_account_attribution_lock_chirho(root_path_chirho, || {
        freeze_account_unlocked_chirho(
            root_path_chirho,
            &AccountCoordinateChirho::from_principal_chirho("user/a").unwrap(),
            "account-close",
        )
    })
    .unwrap();
    for bytes_chirho in [
        prompt_chirho.as_slice(),
        b"a new prompt after the close".as_slice(),
    ] {
        let error_chirho = request_chirho(root_path_chirho, "user/a", bytes_chirho).unwrap_err();
        assert_eq!(
            error_chirho
                .downcast_ref::<AccountAttributionErrorChirho>()
                .unwrap_or_else(|| panic!("not a named refusal: {error_chirho}"))
                .identity_chirho,
            AccountAttributionRefusalChirho::AccountFrozenChirho
        );
    }
    // A's subject is erased through the one canonical path: B's evidence for the same bytes survives.
    crate::privacy_chirho::erase_subject_data_chirho(
        root_path_chirho,
        &a_subject_chirho,
        "user/a",
        "account-close",
    )
    .unwrap();
    let (b_again_chirho, _, _) = request_chirho(root_path_chirho, "user/b", prompt_chirho).unwrap();
    assert_eq!(b_again_chirho, prompt_chirho);
}
