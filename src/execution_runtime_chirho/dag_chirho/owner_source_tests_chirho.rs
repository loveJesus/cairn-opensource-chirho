// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! A private DAG value's owner source: it resolves from the run's request or declaration, never defaults, travels through inheritance as part of the domain, and an ambiguous or owner-changed domain refuses (gpt #28935).

use super::*;
use crate::dag_private_value_chirho::{
    PrivateDagValueContextChirho, PrivateDagValueResolverChirho, PrivateValueOwnerChirho,
    RunAttributionSourceChirho, ValueStoragePolicyChirho,
};
use crate::privacy_chirho::BlobContainerChirho;
use cairn_account_attribution_chirho::AccountCoordinateChirho;

fn context_chirho() -> RequestContextChirho {
    RequestContextChirho {
        user_principal_chirho: "user/b".to_owned(),
        app_chirho: "owner-source-app-chirho".to_owned(),
        owner_principal_chirho: "owner/a".to_owned(),
        client_id_chirho: "client-chirho".to_owned(),
        token_hash_chirho: "0".repeat(64),
        price_book_chirho: None,
        billing_policy_chirho: None,
        key_limit_chirho: None,
    }
}

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

fn coordinate_chirho(principal_chirho: &str) -> AccountCoordinateChirho {
    AccountCoordinateChirho::from_principal_chirho(principal_chirho).unwrap()
}

#[test]
fn a_request_resolves_the_actor_to_itself_and_the_container_to_the_owner_chirho() {
    let context_chirho = context_chirho();
    let source_chirho = RunAttributionSourceChirho::new_chirho(Some(&context_chirho), None);
    let actor_chirho = source_chirho
        .resolve_chirho(PrivateValueOwnerChirho::RequestActorChirho)
        .unwrap();
    assert_eq!(
        actor_chirho.container_chirho(),
        &BlobContainerChirho::AccountChirho(coordinate_chirho("user/b"))
    );
    assert_eq!(
        actor_chirho.actor_chirho(),
        Some(&coordinate_chirho("user/b"))
    );
    let container_chirho = source_chirho
        .resolve_chirho(PrivateValueOwnerChirho::AppContainerChirho)
        .unwrap();
    assert_eq!(
        container_chirho.container_chirho(),
        &BlobContainerChirho::AccountChirho(coordinate_chirho("owner/a"))
    );
    assert_eq!(
        container_chirho.actor_chirho(),
        Some(&coordinate_chirho("user/b"))
    );
}

#[test]
fn a_run_with_no_request_and_no_declaration_refuses_before_any_key_chirho() {
    let root_chirho = fresh_root_chirho("owner-source");
    let error_chirho = crate::dag_private_value_chirho::store_dag_value_with_policy_chirho(
        root_chirho.as_path(),
        b"private bytes with no owner",
        &ValueStoragePolicyChirho::PrivateBlobRefChirho {
            subject_chirho: "app-subject-chirho:owner-source-app-chirho".to_owned(),
            owner_chirho: PrivateValueOwnerChirho::AppContainerChirho,
        },
        PrivateDagValueContextChirho::default(),
        None,
        &RunAttributionSourceChirho::new_chirho(None, None),
    )
    .unwrap_err();
    assert!(
        error_chirho
            .to_string()
            .starts_with("MissingRunAttributionChirho"),
        "{error_chirho}"
    );
    assert!(
        !root_chirho.as_path().join("privacy-keys-chirho").exists()
            || std::fs::read_dir(root_chirho.as_path().join("privacy-keys-chirho"))
                .unwrap()
                .next()
                .is_none(),
        "a refused store made a key"
    );
}

#[test]
fn the_same_bytes_under_two_domains_are_ambiguous_and_refuse_inheritance_chirho() {
    let mut resolver_chirho = PrivateDagValueResolverChirho::default();
    let hash_chirho = resolver_chirho.insert_private_bytes_chirho(
        "user/b",
        PrivateValueOwnerChirho::RequestActorChirho,
        b"equal value",
    );
    // The same domain again is not ambiguous.
    resolver_chirho.insert_private_hash_chirho(
        "user/b",
        PrivateValueOwnerChirho::RequestActorChirho,
        &hash_chirho,
    );
    assert_eq!(
        resolver_chirho
            .domain_for_hash_chirho(&hash_chirho)
            .unwrap(),
        Some((
            "user/b".to_owned(),
            PrivateValueOwnerChirho::RequestActorChirho
        ))
    );
    // An app-owned branch computing the same bytes must not hand its domain to either side.
    resolver_chirho.insert_private_bytes_chirho(
        "app-subject-chirho:owner-source-app-chirho",
        PrivateValueOwnerChirho::AppContainerChirho,
        b"equal value",
    );
    let error_chirho = resolver_chirho
        .domain_for_hash_chirho(&hash_chirho)
        .unwrap_err();
    assert!(
        error_chirho
            .to_string()
            .starts_with("PrivateValueDomainAmbiguousChirho"),
        "{error_chirho}"
    );
    let mut inputs_chirho = BTreeMap::new();
    inputs_chirho.insert("in".to_owned(), hash_chirho);
    assert!(inherited_private_subject_chirho(&inputs_chirho, &resolver_chirho).is_err());
}

#[test]
fn an_output_cannot_keep_the_subject_but_change_its_owner_chirho() {
    let node_chirho = HashChirho("1".repeat(64));
    let inherited_chirho = Some((
        "user/b".to_owned(),
        PrivateValueOwnerChirho::RequestActorChirho,
    ));
    // A public declaration takes the inherited domain whole.
    assert_eq!(
        propagated_output_storage_policy_chirho(
            ValueStoragePolicyChirho::PublicCasChirho,
            inherited_chirho.clone(),
            &node_chirho,
            "out",
        )
        .unwrap(),
        ValueStoragePolicyChirho::PrivateBlobRefChirho {
            subject_chirho: "user/b".to_owned(),
            owner_chirho: PrivateValueOwnerChirho::RequestActorChirho,
        }
    );
    // The same subject string declared under the app owner is a rebinding, not a coincidence.
    assert!(propagated_output_storage_policy_chirho(
        ValueStoragePolicyChirho::PrivateBlobRefChirho {
            subject_chirho: "user/b".to_owned(),
            owner_chirho: PrivateValueOwnerChirho::AppContainerChirho,
        },
        inherited_chirho,
        &node_chirho,
        "out",
    )
    .is_err());
}
