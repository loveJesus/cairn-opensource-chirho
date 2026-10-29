// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The tenant-side publication door and the status road, on a real platform root with a prepared
//! tenant root: an intent is recorded and declassifies exactly its params; a stale version writes
//! nothing public; replay is exact; the status read lists only verified rows and fails closed on a
//! forged platform record; the reserved prefix is read-only.

use super::status_chirho::{
    PublicationStatusResponseChirho, DARK_PUBLICATION_BASE_CHIRHO,
    PUBLICATION_STATUS_REQUEST_SCHEMA_CHIRHO, PUBLICATION_STATUS_RESPONSE_SCHEMA_CHIRHO,
};
use super::*;
use crate::effect_chirho::run_effect_with_context_chirho;
use crate::model_chirho::{CapabilityChirho, DagChirho};
use crate::resource_chirho::{
    ResourceActionPolicyChirho, ResourceChargeChirho, ResourceMeterChirho, ResourceOverageChirho,
};
use crate::tenant_chirho::prepare_tenant_root_chirho;
use base64::{engine::general_purpose::STANDARD as BASE64_CHIRHO, Engine as _};
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) const TEMPLATE_CHIRHO: &str = "page-template-chirho";
pub(super) const KEY_CHIRHO: &str = "page-document-chirho";

pub(super) fn tmp_platform_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-publication-{label_chirho}-{}-{counter_chirho}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

pub(super) struct WorldChirho {
    pub(super) platform_chirho: PathBuf,
    pub(super) tenant_chirho: PathBuf,
    pub(super) context_chirho: RequestContextChirho,
}

/// A platform root with one prepared tenant root holding the workspace app (its ONE customer
/// app, with the resource policy that admits publication intents), one registered user, her
/// session context, and the platform's own signer warmed (a platform-side record needs its key).
pub(super) fn world_chirho(label_chirho: &str) -> WorldChirho {
    let platform_chirho = tmp_platform_root_chirho(label_chirho);
    let tenant_chirho = prepare_tenant_root_chirho(&platform_chirho, "beta-chirho").unwrap();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &tenant_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let dag_chirho = store_chirho::put_object_chirho(
        &tenant_chirho,
        &DagChirho {
            nodes_chirho: Vec::new(),
            edges_chirho: Vec::new(),
        },
    )
    .unwrap();
    crate::app_chirho::deploy_app_chirho(
        &tenant_chirho,
        "perffection-workspace",
        dag_chirho,
        &owner_chirho,
    )
    .unwrap();
    crate::resource_chirho::set_resource_policy_chirho(
        &tenant_chirho,
        "perffection-workspace",
        &owner_chirho,
        vec![ResourceMeterChirho {
            resource_chirho: "publications-chirho".to_string(),
            unit_chirho: "intent-chirho".to_string(),
            stack_chirho: None,
            per_user_limit_chirho: Some(16),
            app_limit_chirho: None,
            window_ms_chirho: None,
            overage_chirho: ResourceOverageChirho::FailClosedChirho,
        }],
        vec![ResourceActionPolicyChirho {
            section_chirho: PUBLICATION_RESOURCE_SECTION_CHIRHO.to_string(),
            action_chirho: PUBLICATION_RESOURCE_ACTION_CHIRHO.to_string(),
            effect_chirho: Some(PUBLICATION_INTENT_EFFECT_CHIRHO.to_string()),
            allow_anonymous_chirho: false,
            charges_chirho: vec![ResourceChargeChirho {
                resource_chirho: "publications-chirho".to_string(),
                amount_chirho: 1,
            }],
        }],
    )
    .unwrap();
    let user_chirho = identity_chirho::register_identity_chirho(
        &tenant_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
    )
    .unwrap()
    .principal_chirho;
    signer_chirho::pubkey_hex_chirho(&platform_chirho).unwrap();
    WorldChirho {
        platform_chirho,
        tenant_chirho,
        context_chirho: RequestContextChirho {
            user_principal_chirho: user_chirho,
            app_chirho: "perffection-workspace".to_string(),
            owner_principal_chirho: "owner/workspace-chirho".to_string(),
            client_id_chirho: "browser-session-chirho".to_string(),
            token_hash_chirho: "token-publication-chirho".to_string(),
            price_book_chirho: None,
            billing_policy_chirho: None,
            key_limit_chirho: None,
        },
    }
}

/// One saved page version through the real viewer-state door, so the head is verified state.
pub(super) fn save_version_chirho(
    world_chirho: &WorldChirho,
    expected_chirho: Option<u64>,
    text_chirho: &[u8],
) {
    let request_chirho = serde_json::json!({
        "schema_chirho": "viewer-state-request-v1-chirho",
        "action_chirho": "write-chirho",
        "key_chirho": KEY_CHIRHO,
        "expected_current_version_chirho": expected_chirho,
        "value_base64_chirho": BASE64_CHIRHO.encode(text_chirho),
    });
    run_effect_with_context_chirho(
        &world_chirho.tenant_chirho,
        0,
        HashChirho(format!("save-{}-chirho", expected_chirho.unwrap_or(0))),
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "viewer-state-chirho/".to_string(),
        },
        &serde_json::to_vec(&request_chirho).unwrap(),
        Some(&world_chirho.context_chirho),
    )
    .expect("save a page version");
}

pub(super) fn head_binding_chirho(
    world_chirho: &WorldChirho,
) -> PublicationViewerStateBindingChirho {
    let head_chirho = effect_chirho::with_verified_head_value_for_key_chirho(
        &world_chirho.tenant_chirho,
        &world_chirho.context_chirho,
        KEY_CHIRHO,
        |head_chirho| Ok(head_chirho.map(|head_chirho| head_chirho.head_chirho)),
    )
    .unwrap()
    .expect("a saved version");
    PublicationViewerStateBindingChirho {
        key_chirho: KEY_CHIRHO.to_string(),
        version_chirho: head_chirho.version_chirho,
        receipt_digest_chirho: Some(head_chirho.receipt_digest_chirho),
    }
}

pub(super) fn publish_request_chirho(
    kind_chirho: &str,
    slug_chirho: &str,
    idem_chirho: &str,
    params_chirho: Option<serde_json::Value>,
    params_hash_chirho: Option<&str>,
    binding_chirho: Option<&PublicationViewerStateBindingChirho>,
) -> Vec<u8> {
    let mut request_chirho = serde_json::json!({
        "schema_chirho": "template-app-deploy-request-v1-chirho",
        "kind_chirho": kind_chirho,
        "slug_chirho": slug_chirho,
        "idem_key_chirho": idem_chirho,
    });
    if let Some(params_chirho) = params_chirho {
        request_chirho["params_chirho"] = params_chirho;
    }
    if let Some(hash_chirho) = params_hash_chirho {
        request_chirho["params_hash_chirho"] = serde_json::Value::String(hash_chirho.to_string());
    }
    if let Some(binding_chirho) = binding_chirho {
        request_chirho["viewer_state_chirho"] = serde_json::to_value(binding_chirho).unwrap();
    }
    serde_json::to_vec(&request_chirho).unwrap()
}

pub(super) fn intend_chirho(world_chirho: &WorldChirho, request_chirho: &[u8]) -> Result<Vec<u8>> {
    crate::app_chirho::run_template_app_deploy_effect_chirho(
        &world_chirho.tenant_chirho,
        TEMPLATE_CHIRHO,
        request_chirho,
        Some(&world_chirho.context_chirho),
    )
}

/// The door's typed refusal — a 200 body on the same road, never an engine error.
pub(super) fn refusal_chirho(bytes_chirho: &[u8]) -> PublicationIntentRefusalChirho {
    let refusal_chirho: PublicationIntentRefusalChirho =
        serde_json::from_slice(bytes_chirho).expect("a typed publication refusal");
    assert_eq!(
        refusal_chirho.schema_chirho,
        PUBLICATION_INTENT_REFUSAL_SCHEMA_CHIRHO
    );
    assert!(PUBLICATION_DOOR_REFUSAL_CODES_CHIRHO
        .contains(&refusal_chirho.refusal_code_chirho.as_str()));
    refusal_chirho
}

pub(super) fn intend_refused_chirho(
    world_chirho: &WorldChirho,
    request_chirho: &[u8],
) -> PublicationIntentRefusalChirho {
    refusal_chirho(&intend_chirho(world_chirho, request_chirho).expect("the door answers, typed"))
}

pub(super) fn page_chirho(title_chirho: &str) -> serde_json::Value {
    serde_json::json!({ "schema_chirho": "page-document-v2-chirho", "title_chirho": title_chirho })
}

/// The bytes she SAVES: the same document in a deliberately non-canonical encoding (key order,
/// spacing), so the raw saved bytes and the canonical object the door declassifies have
/// different content addresses and an assertion between them can fail.
pub(super) fn saved_page_bytes_chirho(title_chirho: &str) -> Vec<u8> {
    format!(
        "{{ \"title_chirho\": \"{title_chirho}\",  \"schema_chirho\": \"page-document-v2-chirho\" }}"
    )
    .into_bytes()
}

#[test]
fn publish_intent_is_recorded_declassifies_exactly_its_params_and_replays_exactly_chirho() {
    let world_chirho = world_chirho("publish");
    save_version_chirho(&world_chirho, None, &saved_page_bytes_chirho("Good Earth"));
    let binding_chirho = head_binding_chirho(&world_chirho);
    // R1 pick (b): under a binding the request carries NO document; the door publishes the
    // saved version's own bytes.
    let request_chirho = publish_request_chirho(
        "publish-chirho",
        "good-earth-bakery",
        "attempt-1",
        None,
        None,
        Some(&binding_chirho),
    );
    let bytes_chirho = intend_chirho(&world_chirho, &request_chirho).expect("intent accepted");
    let response_chirho: PublicationIntentResponseChirho =
        serde_json::from_slice(&bytes_chirho).unwrap();
    assert_eq!(
        response_chirho.schema_chirho,
        PUBLICATION_INTENT_RESPONSE_SCHEMA_CHIRHO
    );
    assert_eq!(
        response_chirho.kind_chirho,
        PublicationKindChirho::PublishChirho
    );
    assert_eq!(response_chirho.app_chirho, "good-earth-bakery");
    assert_eq!(
        response_chirho.address_chirho,
        "/app-chirho/good-earth-bakery/"
    );
    assert_eq!(
        response_chirho.viewer_state_chirho.as_ref(),
        Some(&binding_chirho)
    );
    assert!(!response_chirho.applied_chirho);

    // The declassification wrote exactly the approved document — the canonical object of the
    // version she saved — into the TENANT's public CAS, and nothing else of hers: the raw saved
    // bytes (a different address) are not there.
    let params_chirho = store_chirho::hash_object_chirho(&page_chirho("Good Earth")).unwrap();
    assert_eq!(response_chirho.params_chirho, params_chirho);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(
            &cas_chirho::get_chirho(&world_chirho.tenant_chirho, &params_chirho).unwrap()
        )
        .unwrap(),
        page_chirho("Good Earth")
    );
    let raw_saved_chirho = cas_chirho::hash_chirho(&saved_page_bytes_chirho("Good Earth"));
    assert_ne!(
        raw_saved_chirho, params_chirho,
        "the fixture's two encodings must differ"
    );
    assert!(cas_chirho::get_chirho(&world_chirho.tenant_chirho, &raw_saved_chirho).is_err());
    assert!(
        cas_chirho::get_chirho(&world_chirho.platform_chirho, &params_chirho).is_err(),
        "the tenant door never writes the platform root"
    );

    let records_chirho =
        load_verified_publication_intents_chirho(&world_chirho.tenant_chirho).unwrap();
    assert_eq!(records_chirho.len(), 1);
    assert_eq!(
        publication_intent_digest_chirho(&records_chirho[0]).unwrap(),
        response_chirho.intent_digest_chirho
    );
    assert_eq!(
        records_chirho[0].user_principal_chirho,
        world_chirho.context_chirho.user_principal_chirho
    );

    // Exact replay: same key, same bytes, byte-identical answer, still one record.
    let replay_chirho = intend_chirho(&world_chirho, &request_chirho).unwrap();
    assert_eq!(replay_chirho, bytes_chirho);
    assert_eq!(
        verify_publication_intents_chirho(&world_chirho.tenant_chirho).unwrap(),
        1
    );

    // Same key, different bytes (another slug): refused, nothing new recorded.
    let changed_chirho = publish_request_chirho(
        "publish-chirho",
        "good-earth-bakery-two",
        "attempt-1",
        None,
        None,
        Some(&binding_chirho),
    );
    let error_chirho = intend_chirho(&world_chirho, &changed_chirho)
        .unwrap_err()
        .to_string();
    assert!(
        error_chirho.contains("reused with different request bytes"),
        "{error_chirho}"
    );
    assert_eq!(
        verify_publication_intents_chirho(&world_chirho.tenant_chirho).unwrap(),
        1
    );
    let _ = std::fs::remove_dir_all(&world_chirho.platform_chirho);
}

#[test]
fn stale_version_is_refused_before_anything_public_is_written_chirho() {
    let world_chirho = world_chirho("stale");
    save_version_chirho(&world_chirho, None, &saved_page_bytes_chirho("Stale"));
    let head_chirho = head_binding_chirho(&world_chirho);
    save_version_chirho(
        &world_chirho,
        Some(1),
        &saved_page_bytes_chirho("Stale two"),
    );
    // She approved version 1; the head is now 2.
    let request_chirho = publish_request_chirho(
        "publish-chirho",
        "stale-slug",
        "attempt-stale",
        None,
        None,
        Some(&head_chirho),
    );
    let refusal_chirho = intend_refused_chirho(&world_chirho, &request_chirho);
    assert_eq!(refusal_chirho.refusal_code_chirho, "version-stale-chirho");
    assert_eq!(refusal_chirho.head_version_chirho, Some(2));
    for title_chirho in ["Stale", "Stale two"] {
        let params_chirho = store_chirho::hash_object_chirho(&page_chirho(title_chirho)).unwrap();
        assert!(
            cas_chirho::get_chirho(&world_chirho.tenant_chirho, &params_chirho).is_err(),
            "a stale act must leave nothing public behind"
        );
    }
    assert_eq!(
        verify_publication_intents_chirho(&world_chirho.tenant_chirho).unwrap(),
        0
    );

    // A wrong receipt digest at the right version is stale too.
    let mut forged_chirho = head_binding_chirho(&world_chirho);
    forged_chirho.receipt_digest_chirho = Some(HashChirho("0".repeat(64)));
    let request_chirho = publish_request_chirho(
        "publish-chirho",
        "stale-slug",
        "attempt-forged",
        None,
        None,
        Some(&forged_chirho),
    );
    assert_eq!(
        intend_refused_chirho(&world_chirho, &request_chirho).refusal_code_chirho,
        "version-stale-chirho"
    );
    let _ = std::fs::remove_dir_all(&world_chirho.platform_chirho);
}

#[test]
fn kinds_carry_the_right_payload_and_nothing_else_chirho() {
    let world_chirho = world_chirho("kinds");
    let prior_chirho = "ab".repeat(32);
    let cases_chirho: Vec<(&str, Vec<u8>, &str)> = vec![
        (
            "rollback-without-hash",
            publish_request_chirho("rollback-chirho", "site", "r1", None, None, None),
            "rollback requires params_hash_chirho",
        ),
        (
            "rollback-with-params",
            publish_request_chirho(
                "rollback-chirho",
                "site",
                "r2",
                Some(page_chirho("x")),
                Some(&prior_chirho),
                None,
            ),
            "carries no params_chirho",
        ),
        (
            "publish-with-hash",
            publish_request_chirho(
                "publish-chirho",
                "site",
                "p1",
                Some(page_chirho("x")),
                Some(&prior_chirho),
                None,
            ),
            "only for rollback",
        ),
        (
            "publish-without-params",
            publish_request_chirho("publish-chirho", "site", "p2", None, None, None),
            "required to publish",
        ),
        (
            "bad-slug",
            publish_request_chirho(
                "publish-chirho",
                "Bad_Slug",
                "p3",
                Some(page_chirho("x")),
                None,
                None,
            ),
            "lowercase",
        ),
    ];
    for (label_chirho, request_chirho, needle_chirho) in cases_chirho {
        // The reason is asserted at the validator; the door answers every shape failure with one
        // typed `request-invalid-chirho` body whose sentence never echoes the request.
        let error_chirho = validate_request_chirho(TEMPLATE_CHIRHO, &request_chirho)
            .expect_err(label_chirho)
            .to_string();
        assert!(
            error_chirho.contains(needle_chirho),
            "{label_chirho}: {error_chirho}"
        );
        let refusal_chirho = intend_refused_chirho(&world_chirho, &request_chirho);
        assert_eq!(
            refusal_chirho.refusal_code_chirho, "request-invalid-chirho",
            "{label_chirho}"
        );
        assert!(
            !refusal_chirho.message_chirho.contains("site"),
            "{label_chirho}"
        );
    }
    assert_eq!(
        verify_publication_intents_chirho(&world_chirho.tenant_chirho).unwrap(),
        0
    );

    // A well-formed rollback intent records the prior hash and writes nothing to CAS.
    let request_chirho = publish_request_chirho(
        "rollback-chirho",
        "site",
        "r3",
        None,
        Some(&prior_chirho),
        None,
    );
    let response_chirho: PublicationIntentResponseChirho =
        serde_json::from_slice(&intend_chirho(&world_chirho, &request_chirho).unwrap()).unwrap();
    assert_eq!(
        response_chirho.kind_chirho,
        PublicationKindChirho::RollbackChirho
    );
    assert_eq!(response_chirho.params_chirho.0, prior_chirho);
    assert!(cas_chirho::get_chirho(
        &world_chirho.tenant_chirho,
        &HashChirho(prior_chirho.clone())
    )
    .is_err());
    assert_eq!(
        verify_publication_intents_chirho(&world_chirho.tenant_chirho).unwrap(),
        1
    );
    let _ = std::fs::remove_dir_all(&world_chirho.platform_chirho);
}

pub(super) fn status_read_chirho(
    world_chirho: &WorldChirho,
    prefix_chirho: &str,
    slug_chirho: Option<&str>,
) -> Result<Vec<u8>> {
    let mut request_chirho =
        serde_json::json!({ "schema_chirho": PUBLICATION_STATUS_REQUEST_SCHEMA_CHIRHO });
    if let Some(slug_chirho) = slug_chirho {
        request_chirho["slug_chirho"] = serde_json::Value::String(slug_chirho.to_string());
    }
    let effect_chirho = run_effect_with_context_chirho(
        &world_chirho.tenant_chirho,
        1,
        HashChirho(format!(
            "status-{}-chirho",
            cas_chirho::hash_chirho(prefix_chirho.as_bytes()).0
        )),
        CapabilityChirho::ReadStoreChirho {
            prefix_chirho: prefix_chirho.to_string(),
        },
        &serde_json::to_vec(&request_chirho).unwrap(),
        Some(&world_chirho.context_chirho),
    )?;
    let response_hash_chirho = effect_chirho.response_chirho.expect("status response");
    Ok(cas_chirho::get_chirho(
        &world_chirho.tenant_chirho,
        &response_hash_chirho,
    )?)
}

#[test]
fn status_read_lists_verified_intents_and_platform_outcomes_and_fails_closed_on_a_forged_row_chirho(
) {
    let world_chirho = world_chirho("status");
    save_version_chirho(&world_chirho, None, &saved_page_bytes_chirho("Good Earth"));
    let binding_chirho = head_binding_chirho(&world_chirho);
    let request_chirho = publish_request_chirho(
        "publish-chirho",
        "good-earth-bakery",
        "attempt-1",
        None,
        None,
        Some(&binding_chirho),
    );
    let response_chirho: PublicationIntentResponseChirho =
        serde_json::from_slice(&intend_chirho(&world_chirho, &request_chirho).unwrap()).unwrap();

    // Before any platform outcome: one intent, no applied rows, no live.
    let status_chirho: PublicationStatusResponseChirho = serde_json::from_slice(
        &status_read_chirho(&world_chirho, PUBLICATION_CAPABILITY_PREFIX_CHIRHO, None).unwrap(),
    )
    .unwrap();
    assert_eq!(
        status_chirho.schema_chirho,
        PUBLICATION_STATUS_RESPONSE_SCHEMA_CHIRHO
    );
    assert_eq!(status_chirho.slugs_chirho.len(), 1);
    assert_eq!(status_chirho.slugs_chirho[0].intents_chirho.len(), 1);
    assert_eq!(
        status_chirho.slugs_chirho[0].intents_chirho[0].intent_digest_chirho,
        response_chirho.intent_digest_chirho
    );
    assert!(status_chirho.slugs_chirho[0].applied_chirho.is_empty());
    assert!(status_chirho.slugs_chirho[0].live_chirho.is_none());

    // The platform applies it (brick 2's record, written here through the same appender), plus a
    // refusal for someone ELSE's intent, which must not appear in her view.
    append_publication_applied_record_chirho(
        &world_chirho.platform_chirho,
        PublicationAppliedInputChirho {
            tenant_chirho: "beta-chirho".to_string(),
            intent_digest_chirho: response_chirho.intent_digest_chirho.clone(),
            user_digest_chirho: publication_user_digest_chirho(
                &world_chirho.context_chirho.user_principal_chirho,
            ),
            kind_chirho: PublicationKindChirho::PublishChirho,
            slug_chirho: "good-earth-bakery".to_string(),
            outcome_chirho: PublicationOutcomeChirho::AppliedChirho,
            refusal_code_chirho: None,
            params_chirho: Some(response_chirho.params_chirho.clone()),
            params_record_seq_chirho: Some(0),
        },
    )
    .unwrap();
    append_publication_applied_record_chirho(
        &world_chirho.platform_chirho,
        PublicationAppliedInputChirho {
            tenant_chirho: "beta-chirho".to_string(),
            intent_digest_chirho: HashChirho("cd".repeat(32)),
            user_digest_chirho: publication_user_digest_chirho("user/someone-else-chirho"),
            kind_chirho: PublicationKindChirho::PublishChirho,
            slug_chirho: "good-earth-bakery".to_string(),
            outcome_chirho: PublicationOutcomeChirho::RefusedChirho,
            refusal_code_chirho: Some("slug-taken-chirho".to_string()),
            params_chirho: None,
            params_record_seq_chirho: None,
        },
    )
    .unwrap();
    let status_chirho: PublicationStatusResponseChirho = serde_json::from_slice(
        &status_read_chirho(
            &world_chirho,
            PUBLICATION_CAPABILITY_PREFIX_CHIRHO,
            Some("good-earth-bakery"),
        )
        .unwrap(),
    )
    .unwrap();
    let slug_chirho = &status_chirho.slugs_chirho[0];
    assert_eq!(
        slug_chirho.applied_chirho.len(),
        1,
        "another viewer's outcome is not hers"
    );
    assert_eq!(
        slug_chirho.applied_chirho[0].outcome_chirho,
        PublicationOutcomeChirho::AppliedChirho
    );
    let live_chirho = slug_chirho.live_chirho.as_ref().expect("live after apply");
    assert_eq!(live_chirho.params_chirho, response_chirho.params_chirho);
    assert_eq!(
        live_chirho.applied_intent_digest_chirho,
        response_chirho.intent_digest_chirho
    );
    assert_eq!(
        verify_publication_applied_chirho(&world_chirho.platform_chirho).unwrap(),
        2
    );

    // Forge a platform row (a valid-looking record with a bad signature): the whole read fails
    // closed rather than listing what it can.
    let path_chirho = publication_applied_path_chirho(&world_chirho.platform_chirho);
    let mut lines_chirho: Vec<String> = std::fs::read_to_string(&path_chirho)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    let mut forged_chirho: PublicationAppliedRecordChirho =
        serde_json::from_str(&lines_chirho[0]).unwrap();
    forged_chirho.seq_chirho = 2;
    forged_chirho.slug_chirho = "forged-slug".to_string();
    forged_chirho.intent_digest_chirho = HashChirho("ef".repeat(32));
    lines_chirho.push(serde_json::to_string(&forged_chirho).unwrap());
    std::fs::write(&path_chirho, format!("{}\n", lines_chirho.join("\n"))).unwrap();
    let error_chirho =
        status_read_chirho(&world_chirho, PUBLICATION_CAPABILITY_PREFIX_CHIRHO, None)
            .unwrap_err()
            .to_string();
    assert!(error_chirho.contains("signature invalid"), "{error_chirho}");
    let _ = std::fs::remove_dir_all(&world_chirho.platform_chirho);
}

#[test]
fn publication_prefix_is_exact_and_read_only_chirho() {
    let world_chirho = world_chirho("prefix");
    let error_chirho = status_read_chirho(&world_chirho, "publication-chirho/wider", None)
        .unwrap_err()
        .to_string();
    assert!(
        error_chirho.contains("exact capability prefix"),
        "{error_chirho}"
    );

    let write_chirho = run_effect_with_context_chirho(
        &world_chirho.tenant_chirho,
        2,
        HashChirho("write-into-publication-chirho".to_string()),
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: PUBLICATION_CAPABILITY_PREFIX_CHIRHO.to_string(),
        },
        br#"{"schema_chirho":"scoped-write-store-request-v1-chirho","key_chirho":"publication-chirho/x","value_base64_chirho":"eA=="}"#,
        Some(&world_chirho.context_chirho),
    )
    .unwrap_err()
    .to_string();
    assert!(
        write_chirho.contains("read-only") || write_chirho.contains("reserved"),
        "{write_chirho}"
    );
    let _ = std::fs::remove_dir_all(&world_chirho.platform_chirho);
}

/// The served plain-input path injects `user_principal_chirho` (from the verified session) and
/// `app_params_chirho` into every JSON object body. The door must accept exactly those two —
/// a strict decoder refused every served intent as invalid until the two-root proof caught it —
/// while a claimed principal that disagrees with the session refuses before anything is written,
/// and any other unknown field still refuses.
#[test]
fn served_injected_fields_are_accepted_and_a_foreign_principal_claim_is_refused_chirho() {
    let world_chirho = world_chirho("served-injection");
    let mut request_chirho: serde_json::Value = serde_json::from_slice(&publish_request_chirho(
        "publish-chirho",
        "injected-slug",
        "attempt-injected",
        Some(page_chirho("Injected")),
        None,
        None,
    ))
    .unwrap();
    request_chirho["user_principal_chirho"] =
        serde_json::Value::String(world_chirho.context_chirho.user_principal_chirho.clone());
    request_chirho["app_params_chirho"] = serde_json::json!({ "theme_chirho": "plain" });
    let response_chirho: PublicationIntentResponseChirho = serde_json::from_slice(
        &intend_chirho(&world_chirho, &serde_json::to_vec(&request_chirho).unwrap())
            .expect("the served shape is accepted"),
    )
    .unwrap();
    assert_eq!(response_chirho.slug_chirho, "injected-slug");

    let mut foreign_chirho = request_chirho.clone();
    foreign_chirho["idem_key_chirho"] = serde_json::Value::String("attempt-foreign".to_string());
    foreign_chirho["slug_chirho"] = serde_json::Value::String("foreign-slug".to_string());
    foreign_chirho["user_principal_chirho"] =
        serde_json::Value::String("user/somebody-else-chirho".to_string());
    let error_chirho = intend_chirho(&world_chirho, &serde_json::to_vec(&foreign_chirho).unwrap())
        .unwrap_err()
        .to_string();
    assert!(
        error_chirho.contains("does not match the signed-in session"),
        "{error_chirho}"
    );
    assert_eq!(
        verify_publication_intents_chirho(&world_chirho.tenant_chirho).unwrap(),
        1,
        "a foreign principal claim records no intent"
    );

    let mut unknown_chirho = request_chirho.clone();
    unknown_chirho["idem_key_chirho"] = serde_json::Value::String("attempt-unknown".to_string());
    unknown_chirho["surprise_chirho"] = serde_json::Value::Bool(true);
    let unknown_bytes_chirho = serde_json::to_vec(&unknown_chirho).unwrap();
    let error_chirho = validate_request_chirho(TEMPLATE_CHIRHO, &unknown_bytes_chirho)
        .unwrap_err()
        .to_string();
    assert!(
        error_chirho.contains("decode publication intent request"),
        "any other unknown field still refuses: {error_chirho}"
    );
    assert_eq!(
        intend_refused_chirho(&world_chirho, &unknown_bytes_chirho).refusal_code_chirho,
        "request-invalid-chirho",
        "a shape failure is a typed refusal on the road, not the host's bare 400"
    );
    let _ = std::fs::remove_dir_all(&world_chirho.platform_chirho);
}

/// Result accounting resolves a seal subject for every read-store effect. The status road is a
/// virtual read under a reserved prefix with no store row behind it and a public-by-construction
/// response, so the resolver must answer `None` there instead of resolving the prefix as a store
/// key (which refused every served status read until the two-root proof caught it).
#[test]
fn status_road_has_no_seal_subject_and_a_real_key_still_resolves_chirho() {
    let world_chirho = world_chirho("status-seal-subject");
    let status_request_chirho = serde_json::to_vec(&serde_json::json!({
        "schema_chirho": "publication-status-request-v1-chirho",
    }))
    .unwrap();
    let subject_chirho = effect_chirho::store_seal_response_subject_chirho(
        &world_chirho.tenant_chirho,
        &CapabilityChirho::ReadStoreChirho {
            prefix_chirho: PUBLICATION_CAPABILITY_PREFIX_CHIRHO.to_string(),
        },
        &status_request_chirho,
        Some(&world_chirho.context_chirho),
    )
    .expect("the reserved status prefix resolves without touching the store");
    assert_eq!(subject_chirho, None);
    // Positive control: a viewer-state read on the same root still resolves her sealed subject.
    save_version_chirho(&world_chirho, None, b"draft");
    let read_request_chirho = serde_json::to_vec(&serde_json::json!({
        "schema_chirho": "viewer-state-request-v1-chirho",
        "action_chirho": "read-chirho",
        "key_chirho": KEY_CHIRHO,
    }))
    .unwrap();
    let sealed_chirho = effect_chirho::store_seal_response_subject_chirho(
        &world_chirho.tenant_chirho,
        &CapabilityChirho::ReadStoreChirho {
            prefix_chirho: "viewer-state-chirho/".to_string(),
        },
        &read_request_chirho,
        Some(&world_chirho.context_chirho),
    )
    .unwrap();
    assert!(
        sealed_chirho.is_some(),
        "a viewer-state read carries her seal subject"
    );
    let _ = std::fs::remove_dir_all(&world_chirho.platform_chirho);
}

/// R1 pick (b): with a version binding the request carries no document — a document beside a
/// binding refuses (never compared), and a saved version that is not a JSON object refuses
/// before anything public is written. Both leave the tenant's public CAS and intent log as they
/// were.
#[test]
fn a_document_beside_a_binding_and_a_non_document_head_both_refuse_before_any_write_chirho() {
    let world_chirho = world_chirho("binding-shapes");
    save_version_chirho(&world_chirho, None, &saved_page_bytes_chirho("Bound"));
    let binding_chirho = head_binding_chirho(&world_chirho);
    let both_chirho = publish_request_chirho(
        "publish-chirho",
        "bound-slug",
        "attempt-both",
        Some(page_chirho("Bound")),
        None,
        Some(&binding_chirho),
    );
    let error_chirho = validate_request_chirho(TEMPLATE_CHIRHO, &both_chirho)
        .unwrap_err()
        .to_string();
    assert!(
        error_chirho.contains("send the version binding or the document, not both"),
        "{error_chirho}"
    );
    assert_eq!(
        intend_refused_chirho(&world_chirho, &both_chirho).refusal_code_chirho,
        "request-invalid-chirho"
    );
    let bound_chirho = store_chirho::hash_object_chirho(&page_chirho("Bound")).unwrap();
    assert!(
        cas_chirho::get_chirho(&world_chirho.tenant_chirho, &bound_chirho).is_err(),
        "a refused shape declassifies nothing"
    );

    // Her next saved version is not a document (free text). Publishing it by binding refuses,
    // and the refusal names the version rather than echoing the bytes.
    save_version_chirho(&world_chirho, Some(1), b"just some notes, not a page");
    let notes_binding_chirho = head_binding_chirho(&world_chirho);
    assert_eq!(notes_binding_chirho.version_chirho, 2);
    let request_chirho = publish_request_chirho(
        "publish-chirho",
        "bound-slug",
        "attempt-notes",
        None,
        None,
        Some(&notes_binding_chirho),
    );
    let refusal_chirho = intend_refused_chirho(&world_chirho, &request_chirho);
    assert_eq!(
        refusal_chirho.refusal_code_chirho,
        "saved-version-not-a-document-chirho"
    );
    assert_eq!(refusal_chirho.head_version_chirho, Some(2));
    assert!(!refusal_chirho.message_chirho.contains("just some notes"));
    assert!(cas_chirho::get_chirho(
        &world_chirho.tenant_chirho,
        &cas_chirho::hash_chirho(b"just some notes, not a page")
    )
    .is_err());
    assert_eq!(
        verify_publication_intents_chirho(&world_chirho.tenant_chirho).unwrap(),
        0
    );
    let _ = std::fs::remove_dir_all(&world_chirho.platform_chirho);
}

/// The linearization point (PFE #21787): the head read, the declassifying write, and the intent
/// append happen inside ONE hold of the viewer-state lock, so a save of hers issued while the
/// door runs cannot land between them. Measured with a real concurrent save: it is blocked
/// while the door's closure runs and lands only after the intent exists.
#[test]
fn a_concurrent_save_waits_for_the_intent_that_binds_the_head_it_would_move_chirho() {
    let world_chirho = world_chirho("linearization");
    save_version_chirho(&world_chirho, None, &saved_page_bytes_chirho("Bound"));
    let binding_chirho = head_binding_chirho(&world_chirho);
    let (entered_tx_chirho, entered_rx_chirho) = std::sync::mpsc::channel::<()>();
    let (release_tx_chirho, release_rx_chirho) = std::sync::mpsc::channel::<()>();
    let saver_root_chirho = world_chirho.tenant_chirho.clone();
    let saver_context_chirho = world_chirho.context_chirho.clone();
    let saved_at_chirho = std::sync::Arc::new(std::sync::Mutex::new(None::<std::time::Instant>));
    let saved_at_for_thread_chirho = saved_at_chirho.clone();

    // Hold the viewer-state lock exactly as the door does, and while holding it start a save on
    // another thread; the save must not complete until the closure returns.
    let outcome_chirho = effect_chirho::with_verified_head_value_for_key_chirho(
        &world_chirho.tenant_chirho,
        &world_chirho.context_chirho,
        KEY_CHIRHO,
        |head_chirho| {
            let head_chirho = head_chirho.expect("a saved version");
            assert_eq!(
                (
                    head_chirho.head_chirho.version_chirho,
                    head_chirho.head_chirho.receipt_digest_chirho.clone()
                ),
                (
                    binding_chirho.version_chirho,
                    binding_chirho.receipt_digest_chirho.clone().unwrap()
                )
            );
            let saver_chirho = std::thread::spawn(move || {
                entered_tx_chirho.send(()).unwrap();
                let request_chirho = serde_json::json!({
                    "schema_chirho": "viewer-state-request-v1-chirho",
                    "action_chirho": "write-chirho",
                    "key_chirho": KEY_CHIRHO,
                    "expected_current_version_chirho": 1,
                    "value_base64_chirho": BASE64_CHIRHO.encode(b"{\"title_chirho\":\"moved\"}"),
                });
                run_effect_with_context_chirho(
                    &saver_root_chirho,
                    0,
                    HashChirho("save-concurrent-chirho".to_string()),
                    CapabilityChirho::WriteStoreChirho {
                        prefix_chirho: "viewer-state-chirho/".to_string(),
                    },
                    &serde_json::to_vec(&request_chirho).unwrap(),
                    Some(&saver_context_chirho),
                )
                .expect("the concurrent save lands once the lock is released");
                *saved_at_for_thread_chirho.lock().unwrap() = Some(std::time::Instant::now());
            });
            entered_rx_chirho.recv().unwrap();
            // Give the saver every chance to race; it must still be blocked on the lock.
            assert!(
                release_rx_chirho
                    .recv_timeout(std::time::Duration::from_millis(300))
                    .is_err(),
                "nobody releases this channel; it is only a bounded wait"
            );
            assert!(
                saved_at_chirho.lock().unwrap().is_none(),
                "the concurrent save landed while the door held the viewer-state lock"
            );
            let closed_at_chirho = std::time::Instant::now();
            Ok((saver_chirho, closed_at_chirho))
        },
    )
    .unwrap();
    drop(release_tx_chirho);
    let (saver_chirho, closed_at_chirho) = outcome_chirho;
    saver_chirho.join().unwrap();
    let saved_at_chirho = saved_at_chirho
        .lock()
        .unwrap()
        .expect("the save landed after");
    assert!(
        saved_at_chirho >= closed_at_chirho,
        "the save must land only after the door's hold ended"
    );
    assert_eq!(head_binding_chirho(&world_chirho).version_chirho, 2);
    let _ = std::fs::remove_dir_all(&world_chirho.platform_chirho);
}

/// PFE #21790 item 3: the receipt digest is engine hashing a guest should not replicate, so
/// (key, version) alone binds on the wire; the door fills the recorded binding with the digest of
/// the head it verified, a supplied digest must still match, and a wrong version is stale.
#[test]
fn a_version_only_binding_is_recorded_with_the_verified_heads_receipt_digest_chirho() {
    let world_chirho = world_chirho("version-only-binding");
    save_version_chirho(&world_chirho, None, &saved_page_bytes_chirho("Bound"));
    let full_chirho = head_binding_chirho(&world_chirho);
    let version_only_chirho = PublicationViewerStateBindingChirho {
        key_chirho: KEY_CHIRHO.to_string(),
        version_chirho: full_chirho.version_chirho,
        receipt_digest_chirho: None,
    };
    let response_chirho: PublicationIntentResponseChirho = serde_json::from_slice(
        &intend_chirho(
            &world_chirho,
            &publish_request_chirho(
                "publish-chirho",
                "bound-slug",
                "attempt-version-only",
                None,
                None,
                Some(&version_only_chirho),
            ),
        )
        .expect("a version-only binding is accepted"),
    )
    .unwrap();
    assert_eq!(
        response_chirho.viewer_state_chirho,
        Some(full_chirho.clone()),
        "the recorded binding carries the verified head's receipt digest"
    );
    let records_chirho =
        load_verified_publication_intents_chirho(&world_chirho.tenant_chirho).unwrap();
    assert_eq!(
        records_chirho[0].viewer_state_chirho,
        Some(full_chirho.clone())
    );

    let wrong_version_chirho = PublicationViewerStateBindingChirho {
        key_chirho: KEY_CHIRHO.to_string(),
        version_chirho: full_chirho.version_chirho + 1,
        receipt_digest_chirho: None,
    };
    let refusal_chirho = intend_refused_chirho(
        &world_chirho,
        &publish_request_chirho(
            "publish-chirho",
            "bound-slug",
            "attempt-wrong-version",
            None,
            None,
            Some(&wrong_version_chirho),
        ),
    );
    assert_eq!(refusal_chirho.refusal_code_chirho, "version-stale-chirho");
    assert_eq!(
        refusal_chirho.head_version_chirho,
        Some(full_chirho.version_chirho)
    );
    let _ = std::fs::remove_dir_all(&world_chirho.platform_chirho);
}

/// Charged units for her publication meter: the sum of every usage record's `publications-chirho`
/// charge — what the 16-per-user allowance actually counts.
pub(super) fn charged_publication_units_chirho(world_chirho: &WorldChirho) -> (usize, i64) {
    let records_chirho =
        crate::resource_chirho::load_resource_usage_chirho(&world_chirho.tenant_chirho).unwrap();
    let units_chirho = records_chirho
        .iter()
        .flat_map(|record_chirho| record_chirho.charges_chirho.iter())
        .filter(|charge_chirho| charge_chirho.resource_chirho == "publications-chirho")
        .map(|charge_chirho| charge_chirho.amount_chirho)
        .sum();
    (records_chirho.len(), units_chirho)
}

/// PFE gpt #21810: a refused fresh attempt must not consume her publication allowance. Every
/// eligibility refusal — stale base, stale version, a saved object that is no document — leaves
/// the usage log, the charged units, the intent log, and the public CAS exactly as they were;
/// an admitted attempt charges exactly one unit.
#[test]
fn refused_attempts_charge_nothing_and_an_admitted_one_charges_one_unit_chirho() {
    let world_chirho = world_chirho("no-charge-on-refusal");
    save_version_chirho(&world_chirho, None, &saved_page_bytes_chirho("Bound"));
    let head_chirho = head_binding_chirho(&world_chirho);
    let before_chirho = (
        charged_publication_units_chirho(&world_chirho),
        verify_publication_intents_chirho(&world_chirho.tenant_chirho).unwrap(),
    );
    let with_base_chirho = |request_chirho: Vec<u8>, base_chirho: &str| -> Vec<u8> {
        let mut value_chirho: serde_json::Value = serde_json::from_slice(&request_chirho).unwrap();
        value_chirho["base_publication_chirho"] =
            serde_json::Value::String(base_chirho.to_string());
        serde_json::to_vec(&value_chirho).unwrap()
    };

    // 1. stale base: the slug is dark, the form claims a live digest.
    let stale_base_chirho = with_base_chirho(
        publish_request_chirho(
            "publish-chirho",
            "bound-slug",
            "a-base",
            None,
            None,
            Some(&head_chirho),
        ),
        &"7".repeat(64),
    );
    let refusal_chirho = intend_refused_chirho(&world_chirho, &stale_base_chirho);
    assert_eq!(refusal_chirho.refusal_code_chirho, "base-moved-chirho");
    assert_eq!(
        refusal_chirho.live_base_chirho.as_deref(),
        Some(DARK_PUBLICATION_BASE_CHIRHO),
        "the refusal carries the live base the form must be re-rendered against"
    );

    // 2. stale version: she names version 2 while the head is 1.
    let mut stale_version_chirho = head_chirho.clone();
    stale_version_chirho.version_chirho += 1;
    assert_eq!(
        intend_refused_chirho(
            &world_chirho,
            &publish_request_chirho(
                "publish-chirho",
                "bound-slug",
                "a-version",
                None,
                None,
                Some(&stale_version_chirho),
            ),
        )
        .refusal_code_chirho,
        "version-stale-chirho"
    );

    // 3. the saved object is not a document.
    save_version_chirho(&world_chirho, Some(1), b"free text, not a page");
    let notes_chirho = head_binding_chirho(&world_chirho);
    assert_eq!(
        intend_refused_chirho(
            &world_chirho,
            &publish_request_chirho(
                "publish-chirho",
                "bound-slug",
                "a-notes",
                None,
                None,
                Some(&notes_chirho),
            ),
        )
        .refusal_code_chirho,
        "saved-version-not-a-document-chirho"
    );

    assert_eq!(
        (
            charged_publication_units_chirho(&world_chirho),
            verify_publication_intents_chirho(&world_chirho.tenant_chirho).unwrap(),
        ),
        (before_chirho.0, before_chirho.1),
        "three refusals: no usage record, no charged unit, no intent"
    );
    // The only public object a publish could add is the document; its address must be absent.
    assert!(cas_chirho::get_chirho(
        &world_chirho.tenant_chirho,
        &store_chirho::hash_object_chirho(&page_chirho("Bound")).unwrap()
    )
    .is_err());

    // 4. an admitted attempt charges exactly one unit and records one intent.
    save_version_chirho(
        &world_chirho,
        Some(2),
        &saved_page_bytes_chirho("Bound again"),
    );
    let good_chirho = head_binding_chirho(&world_chirho);
    let (records_before_chirho, units_before_chirho) =
        charged_publication_units_chirho(&world_chirho);
    intend_chirho(
        &world_chirho,
        &publish_request_chirho(
            "publish-chirho",
            "bound-slug",
            "a-good",
            None,
            None,
            Some(&good_chirho),
        ),
    )
    .expect("admitted");
    assert_eq!(
        charged_publication_units_chirho(&world_chirho),
        (records_before_chirho + 1, units_before_chirho + 1)
    );
    assert_eq!(
        verify_publication_intents_chirho(&world_chirho.tenant_chirho).unwrap(),
        1
    );

    // 5. claude2 #21835: the fix turned one admission call into two, one per road, and only the
    //    binding road was asserted — neutralising the other survived. The SAME assertion on the
    //    no-binding road: a publish that carries its document with the request, and a rollback
    //    that names a prior record, each charge exactly one unit.
    let (records_before_chirho, units_before_chirho) =
        charged_publication_units_chirho(&world_chirho);
    let document_response_chirho: PublicationIntentResponseChirho = serde_json::from_slice(
        &intend_chirho(
            &world_chirho,
            &publish_request_chirho(
                "publish-chirho",
                "document-slug",
                "a-document",
                Some(page_chirho("With document")),
                None,
                None,
            ),
        )
        .expect("admitted on the no-binding road"),
    )
    .unwrap();
    assert_eq!(
        charged_publication_units_chirho(&world_chirho),
        (records_before_chirho + 1, units_before_chirho + 1),
        "a document-carrying publish is billable exactly once"
    );
    intend_chirho(
        &world_chirho,
        &publish_request_chirho(
            "rollback-chirho",
            "document-slug",
            "a-rollback",
            None,
            Some(&document_response_chirho.params_chirho.0),
            None,
        ),
    )
    .expect("a rollback by prior record is admitted on the no-binding road");
    assert_eq!(
        charged_publication_units_chirho(&world_chirho),
        (records_before_chirho + 2, units_before_chirho + 2),
        "a rollback by prior record is billable exactly once"
    );
    assert_eq!(
        verify_publication_intents_chirho(&world_chirho.tenant_chirho).unwrap(),
        3
    );
    let _ = std::fs::remove_dir_all(&world_chirho.platform_chirho);
}

/// PFE #21813 (1): the publishing page is a single-input DAG, so the status road names her
/// verified page head for a requested key — absent before the first save, then version and
/// receipt digest, never value bytes. claude2 #21816: the same road refuses on the platform root
/// instead of silently dropping its tenant scope.
#[test]
fn status_names_her_page_head_for_a_requested_key_and_refuses_on_the_platform_root_chirho() {
    let world_chirho = world_chirho("status-page-head");
    let read_chirho =
        |world_chirho: &WorldChirho, root_chirho: &std::path::Path| -> Result<Vec<u8>> {
            let request_chirho = serde_json::json!({
                "schema_chirho": PUBLICATION_STATUS_REQUEST_SCHEMA_CHIRHO,
                "page_key_chirho": KEY_CHIRHO,
            });
            run_effect_with_context_chirho(
                root_chirho,
                1,
                HashChirho(format!(
                    "status-head-{}-chirho",
                    cas_chirho::hash_chirho(root_chirho.to_string_lossy().as_bytes()).0
                )),
                CapabilityChirho::ReadStoreChirho {
                    prefix_chirho: PUBLICATION_CAPABILITY_PREFIX_CHIRHO.to_string(),
                },
                &serde_json::to_vec(&request_chirho).unwrap(),
                Some(&world_chirho.context_chirho),
            )
            .map(|effect_chirho| {
                cas_chirho::get_chirho(root_chirho, effect_chirho.response_chirho.as_ref().unwrap())
                    .unwrap()
            })
        };
    let before_chirho: PublicationStatusResponseChirho =
        serde_json::from_slice(&read_chirho(&world_chirho, &world_chirho.tenant_chirho).unwrap())
            .unwrap();
    assert_eq!(before_chirho.page_head_chirho, None, "nothing saved yet");
    let bytes_chirho = serde_json::to_vec(&before_chirho).unwrap();
    assert!(
        !String::from_utf8_lossy(&bytes_chirho).contains("page_head_chirho"),
        "an absent head is omitted, not null"
    );

    save_version_chirho(&world_chirho, None, &saved_page_bytes_chirho("Head"));
    let binding_chirho = head_binding_chirho(&world_chirho);
    let after_chirho: PublicationStatusResponseChirho =
        serde_json::from_slice(&read_chirho(&world_chirho, &world_chirho.tenant_chirho).unwrap())
            .unwrap();
    let after_bytes_chirho = serde_json::to_vec(&after_chirho).unwrap();
    let head_chirho = after_chirho.page_head_chirho.expect("her head");
    assert_eq!(head_chirho.key_chirho, KEY_CHIRHO);
    assert_eq!(head_chirho.version_chirho, binding_chirho.version_chirho);
    assert_eq!(
        Some(head_chirho.receipt_digest_chirho),
        binding_chirho.receipt_digest_chirho
    );
    assert!(
        !String::from_utf8_lossy(&after_bytes_chirho).contains("Head"),
        "no value bytes"
    );

    // The platform root is not a status road.
    let error_chirho = read_chirho(&world_chirho, &world_chirho.platform_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("tenant-root road"), "{error_chirho}");
    let _ = std::fs::remove_dir_all(&world_chirho.platform_chirho);
}
