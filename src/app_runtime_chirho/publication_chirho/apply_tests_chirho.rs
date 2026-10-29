// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The platform applier against a real platform root with a prepared tenant: the publish →
//! republish → rollback ladder lands as one app with three params records and three applied
//! records, a rerun applies nothing twice, every refusal token is reachable from a real intent, and
//! a tampered tenant log applies nothing at all.

use super::apply_chirho::*;
use super::status_chirho::{PublicationStatusResponseChirho, DARK_PUBLICATION_BASE_CHIRHO};
use super::tests_chirho::{
    head_binding_chirho, intend_chirho, intend_refused_chirho, page_chirho, publish_request_chirho,
    save_version_chirho, saved_page_bytes_chirho, status_read_chirho, world_chirho, WorldChirho,
    TEMPLATE_CHIRHO,
};
use super::*;
use crate::model_chirho::{CapabilityChirho, DagChirho};

/// The page template registered on the PLATFORM root, as the operator does with
/// `template-registry-set`. An empty DAG is the pure-only template the door's own tests use.
fn register_template_chirho(world_chirho: &WorldChirho) {
    let dag_chirho = store_chirho::put_object_chirho(
        &world_chirho.platform_chirho,
        &DagChirho {
            nodes_chirho: Vec::new(),
            edges_chirho: Vec::new(),
        },
    )
    .unwrap();
    crate::app_chirho::register_template_app_template_chirho(
        &world_chirho.platform_chirho,
        crate::app_chirho::TemplateRegistryInputChirho {
            template_id_chirho: TEMPLATE_CHIRHO.to_string(),
            root_dag_chirho: dag_chirho,
            response_content_type_chirho: "text/html".to_string(),
        },
    )
    .unwrap();
}

fn intend_ok_chirho(
    world_chirho: &WorldChirho,
    request_chirho: &[u8],
) -> PublicationIntentResponseChirho {
    serde_json::from_slice(&intend_chirho(world_chirho, request_chirho).expect("intent accepted"))
        .unwrap()
}

fn apply_chirho(world_chirho: &WorldChirho) -> PublicationApplyReportChirho {
    apply_publication_intents_chirho(&world_chirho.platform_chirho, "beta-chirho")
        .expect("apply runs")
}

fn params_hashes_for_chirho(world_chirho: &WorldChirho, slug_chirho: &str) -> Vec<HashChirho> {
    crate::app_chirho::load_app_params_records_chirho(&world_chirho.platform_chirho)
        .unwrap()
        .into_iter()
        .filter(|record_chirho| record_chirho.app_chirho == slug_chirho)
        .map(|record_chirho| record_chirho.params_chirho)
        .collect()
}

#[test]
fn publish_republish_rollback_apply_in_order_and_a_rerun_applies_nothing_twice_chirho() {
    let world_chirho = world_chirho("apply-ladder");
    register_template_chirho(&world_chirho);
    // v1 is published from her saved version under a binding (R1 pick b: no document on the
    // wire); v2 is republished with the document in the request and no binding — both roads.
    save_version_chirho(
        &world_chirho,
        None,
        &saved_page_bytes_chirho("Good Earth v1"),
    );
    let binding_chirho = head_binding_chirho(&world_chirho);
    let v1_chirho = intend_ok_chirho(
        &world_chirho,
        &publish_request_chirho(
            "publish-chirho",
            "good-earth-bakery",
            "a1",
            None,
            None,
            Some(&binding_chirho),
        ),
    );
    assert_eq!(
        v1_chirho.params_chirho,
        store_chirho::hash_object_chirho(&page_chirho("Good Earth v1")).unwrap(),
        "the published object is the saved version, canonicalized"
    );
    let v2_chirho = intend_ok_chirho(
        &world_chirho,
        &publish_request_chirho(
            "republish-chirho",
            "good-earth-bakery",
            "a2",
            Some(page_chirho("Good Earth v2")),
            None,
            None,
        ),
    );
    let back_chirho = intend_ok_chirho(
        &world_chirho,
        &publish_request_chirho(
            "rollback-chirho",
            "good-earth-bakery",
            "a3",
            None,
            Some(&v1_chirho.params_chirho.0),
            None,
        ),
    );

    let report_chirho = apply_chirho(&world_chirho);
    assert_eq!(
        (
            report_chirho.intents_seen_chirho,
            report_chirho.applied_chirho,
            report_chirho.refused_chirho,
            report_chirho.already_applied_chirho
        ),
        (3, 3, 0, 0),
        "{report_chirho:?}"
    );

    // One app at the platform level, named by the slug, owned by her minted publication owner.
    let owner_chirho = crate::app_chirho::verified_app_owner_chirho(
        &world_chirho.platform_chirho,
        "good-earth-bakery",
    )
    .unwrap()
    .expect("published app exists");
    let owners_chirho =
        load_verified_publication_owners_chirho(&world_chirho.platform_chirho).unwrap();
    assert_eq!(owners_chirho.len(), 1);
    assert_eq!(owners_chirho[0].owner_principal_chirho, owner_chirho);
    assert_eq!(
        owners_chirho[0].user_digest_chirho,
        publication_user_digest_chirho(&world_chirho.context_chirho.user_principal_chirho)
    );
    let claims_chirho = load_verified_slug_claims_chirho(&world_chirho.platform_chirho).unwrap();
    assert_eq!(claims_chirho.len(), 1);
    assert_eq!(
        claims_chirho[0].intent_digest_chirho,
        v1_chirho.intent_digest_chirho
    );

    // Three params records, in order, and the served selection is the rolled-back v1 document.
    assert_eq!(
        params_hashes_for_chirho(&world_chirho, "good-earth-bakery"),
        vec![
            v1_chirho.params_chirho.clone(),
            v2_chirho.params_chirho.clone(),
            v1_chirho.params_chirho.clone()
        ]
    );
    let selected_chirho = crate::app_chirho::app_params_chirho(
        &world_chirho.platform_chirho,
        "good-earth-bakery",
        None,
        &owner_chirho,
    )
    .unwrap()
    .expect("a selected params record");
    assert_eq!(selected_chirho.params_chirho, v1_chirho.params_chirho);
    assert!(
        cas_chirho::get_chirho(&world_chirho.platform_chirho, &v2_chirho.params_chirho).is_ok(),
        "the platform CAS holds the copied document"
    );

    let applied_chirho =
        load_verified_publication_applied_chirho(&world_chirho.platform_chirho).unwrap();
    assert_eq!(applied_chirho.len(), 3);
    assert!(applied_chirho.iter().all(
        |record_chirho| record_chirho.outcome_chirho == PublicationOutcomeChirho::AppliedChirho
    ));
    assert_eq!(
        applied_chirho[2].intent_digest_chirho,
        back_chirho.intent_digest_chirho
    );
    assert_eq!(applied_chirho[2].params_record_seq_chirho, Some(2));

    // Her status view now shows live = the rollback, through the real read road.
    let status_chirho: PublicationStatusResponseChirho = serde_json::from_slice(
        &status_read_chirho(
            &world_chirho,
            PUBLICATION_CAPABILITY_PREFIX_CHIRHO,
            Some("good-earth-bakery"),
        )
        .unwrap(),
    )
    .unwrap();
    let live_chirho = status_chirho.slugs_chirho[0]
        .live_chirho
        .as_ref()
        .expect("live");
    assert_eq!(
        live_chirho.applied_intent_digest_chirho,
        back_chirho.intent_digest_chirho
    );
    assert_eq!(live_chirho.params_chirho, v1_chirho.params_chirho);

    // Idempotent: a rerun sees the same three, applies none, writes nothing.
    let rerun_chirho = apply_chirho(&world_chirho);
    assert_eq!(
        (
            rerun_chirho.already_applied_chirho,
            rerun_chirho.applied_chirho,
            rerun_chirho.refused_chirho
        ),
        (3, 0, 0)
    );
    assert_eq!(
        load_verified_publication_applied_chirho(&world_chirho.platform_chirho)
            .unwrap()
            .len(),
        3
    );
    assert_eq!(
        params_hashes_for_chirho(&world_chirho, "good-earth-bakery").len(),
        3
    );
    let _ = std::fs::remove_dir_all(&world_chirho.platform_chirho);
}

#[test]
fn every_refusal_token_is_reachable_from_a_real_intent_chirho() {
    let world_chirho = world_chirho("apply-refusals");
    register_template_chirho(&world_chirho);
    reserve_publication_slug_chirho(
        &world_chirho.platform_chirho,
        "perffection",
        ReservedSlugReasonChirho::PlatformAppChirho,
    )
    .unwrap();
    // The same reservation twice is one record, whatever reason the second caller names.
    reserve_publication_slug_chirho(
        &world_chirho.platform_chirho,
        "perffection",
        ReservedSlugReasonChirho::OperatorPolicyChirho,
    )
    .unwrap();
    assert_eq!(
        verify_reserved_slugs_chirho(&world_chirho.platform_chirho).unwrap(),
        1
    );

    let a_page_chirho = page_chirho("A");
    intend_ok_chirho(
        &world_chirho,
        &publish_request_chirho(
            "publish-chirho",
            "perffection",
            "r-reserved",
            Some(a_page_chirho.clone()),
            None,
            None,
        ),
    );
    intend_ok_chirho(
        &world_chirho,
        &publish_request_chirho(
            "republish-chirho",
            "never-published",
            "r-notyours",
            Some(a_page_chirho.clone()),
            None,
            None,
        ),
    );
    intend_ok_chirho(
        &world_chirho,
        &publish_request_chirho(
            "publish-chirho",
            "mine",
            "r-ok",
            Some(a_page_chirho.clone()),
            None,
            None,
        ),
    );
    intend_ok_chirho(
        &world_chirho,
        &publish_request_chirho(
            "rollback-chirho",
            "mine",
            "r-prior",
            None,
            Some(&"ab".repeat(32)),
            None,
        ),
    );
    // A params object that will be missing from the tenant CAS by apply time.
    let vanishing_chirho = intend_ok_chirho(
        &world_chirho,
        &publish_request_chirho(
            "publish-chirho",
            "vanishing",
            "r-missing",
            Some(page_chirho("Vanish")),
            None,
            None,
        ),
    );
    let object_chirho = world_chirho
        .tenant_chirho
        .join("objects-chirho")
        .join(&vanishing_chirho.params_chirho.0[..2])
        .join(&vanishing_chirho.params_chirho.0[2..]);
    assert!(
        object_chirho.is_file(),
        "the intent's params object is where the CAS keeps it"
    );
    std::fs::remove_file(&object_chirho).unwrap();

    // The first apply must fail closed: the tenant intent log no longer verifies (its params object
    // is gone), so NOTHING is applied — not even the intents that would have been fine.
    let error_chirho =
        apply_publication_intents_chirho(&world_chirho.platform_chirho, "beta-chirho")
            .unwrap_err()
            .to_string();
    assert!(
        error_chirho.contains("not in the tenant CAS"),
        "{error_chirho}"
    );
    assert_eq!(
        load_verified_publication_applied_chirho(&world_chirho.platform_chirho)
            .unwrap()
            .len(),
        0
    );

    // Put the object back (a different reader may have it), then judge: publish/republish read the
    // tenant CAS by hash, so a tampered object is `params-missing-chirho` at apply time.
    std::fs::write(&object_chirho, b"{\"tampered_chirho\":true}").unwrap();
    let error_chirho =
        apply_publication_intents_chirho(&world_chirho.platform_chirho, "beta-chirho")
            .unwrap_err()
            .to_string();
    assert!(
        error_chirho.contains("content address mismatch")
            || error_chirho.contains("not in the tenant CAS"),
        "{error_chirho}"
    );
    std::fs::write(
        &object_chirho,
        serde_json::to_vec(&page_chirho("Vanish")).unwrap(),
    )
    .unwrap();

    let report_chirho = apply_chirho(&world_chirho);
    assert_eq!(report_chirho.applied_chirho, 2, "{report_chirho:?}");
    assert_eq!(report_chirho.refused_chirho, 3, "{report_chirho:?}");
    assert_eq!(
        report_chirho.refusals_chirho.get("slug-reserved-chirho"),
        Some(&1)
    );
    assert_eq!(
        report_chirho.refusals_chirho.get("not-your-app-chirho"),
        Some(&1)
    );
    assert_eq!(
        report_chirho
            .refusals_chirho
            .get("unknown-prior-params-chirho"),
        Some(&1)
    );
    let _ = std::fs::remove_dir_all(&world_chirho.platform_chirho);
}

#[test]
fn a_second_viewer_cannot_take_a_claimed_slug_and_an_unregistered_template_refuses_chirho() {
    let world_chirho = world_chirho("apply-claims");
    register_template_chirho(&world_chirho);
    intend_ok_chirho(
        &world_chirho,
        &publish_request_chirho(
            "publish-chirho",
            "shared-slug",
            "u1",
            Some(page_chirho("First")),
            None,
            None,
        ),
    );
    assert_eq!(apply_chirho(&world_chirho).applied_chirho, 1);

    // Another viewer of the same tenant intends the same slug. The door now refuses her
    // PRE-ADMISSION with `slug-taken-chirho` (Model B occupancy), so — unlike before — her intent
    // is never recorded and her platform owner is never minted for a doomed attempt.
    let other_chirho = identity_chirho::register_identity_chirho(
        &world_chirho.tenant_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
    )
    .unwrap()
    .principal_chirho;
    let mut other_world_chirho = WorldChirho {
        platform_chirho: world_chirho.platform_chirho.clone(),
        tenant_chirho: world_chirho.tenant_chirho.clone(),
        context_chirho: world_chirho.context_chirho.clone(),
    };
    other_world_chirho.context_chirho.user_principal_chirho = other_chirho;
    let taken_chirho = intend_refused_chirho(
        &other_world_chirho,
        &publish_request_chirho(
            "publish-chirho",
            "shared-slug",
            "u2",
            Some(page_chirho("Second")),
            None,
            None,
        ),
    );
    assert_eq!(taken_chirho.refusal_code_chirho, "slug-taken-chirho");
    assert_eq!(taken_chirho.slug_chirho.as_deref(), Some("shared-slug"));
    assert_eq!(
        taken_chirho.live_base_chirho, None,
        "the occupied-name refusal never echoes the holder's live digest"
    );
    // Her intent was refused before admission: nothing new to apply, and the first viewer's page
    // is untouched.
    let report_chirho = apply_chirho(&world_chirho);
    assert_eq!(
        (
            report_chirho.intents_seen_chirho,
            report_chirho.applied_chirho
        ),
        (1, 0),
        "the second viewer's intent never reached the tenant log: {report_chirho:?}"
    );
    assert_eq!(
        params_hashes_for_chirho(&world_chirho, "shared-slug").len(),
        1,
        "the first viewer's page is untouched"
    );
    assert_eq!(
        load_verified_publication_owners_chirho(&world_chirho.platform_chirho)
            .unwrap()
            .len(),
        1,
        "the door refused pre-admission, so the second viewer's owner was never minted"
    );

    // A template the platform has not registered.
    let request_chirho = {
        let mut value_chirho: serde_json::Value = serde_json::from_slice(&publish_request_chirho(
            "publish-chirho",
            "other-site",
            "u3",
            Some(page_chirho("X")),
            None,
            None,
        ))
        .unwrap();
        value_chirho["template_id_chirho"] =
            serde_json::Value::String("not-registered-chirho".to_string());
        serde_json::to_vec(&value_chirho).unwrap()
    };
    crate::app_chirho::run_template_app_deploy_effect_chirho(
        &world_chirho.tenant_chirho,
        "not-registered-chirho",
        &request_chirho,
        Some(&world_chirho.context_chirho),
    )
    .expect("the tenant door does not need a local registry");
    let report_chirho = apply_chirho(&world_chirho);
    assert_eq!(
        report_chirho.refusals_chirho.get("unknown-template-chirho"),
        Some(&1),
        "{report_chirho:?}"
    );
    let _ = std::fs::remove_dir_all(&world_chirho.platform_chirho);
}

#[test]
fn a_forged_tenant_intent_applies_nothing_chirho() {
    let world_chirho = world_chirho("apply-forged");
    register_template_chirho(&world_chirho);
    intend_ok_chirho(
        &world_chirho,
        &publish_request_chirho(
            "publish-chirho",
            "honest",
            "f1",
            Some(page_chirho("Honest")),
            None,
            None,
        ),
    );
    let path_chirho = publication_intents_path_chirho(&world_chirho.tenant_chirho);
    let mut lines_chirho: Vec<String> = std::fs::read_to_string(&path_chirho)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    let mut forged_chirho: PublicationIntentRecordChirho =
        serde_json::from_str(&lines_chirho[0]).unwrap();
    forged_chirho.seq_chirho = 1;
    forged_chirho.slug_chirho = "forged".to_string();
    forged_chirho.idempotency_key_hash_chirho = HashChirho("ff".repeat(32));
    lines_chirho.push(serde_json::to_string(&forged_chirho).unwrap());
    std::fs::write(&path_chirho, format!("{}\n", lines_chirho.join("\n"))).unwrap();

    let error_chirho =
        apply_publication_intents_chirho(&world_chirho.platform_chirho, "beta-chirho")
            .unwrap_err()
            .to_string();
    assert!(error_chirho.contains("signature invalid"), "{error_chirho}");
    assert_eq!(
        load_verified_publication_applied_chirho(&world_chirho.platform_chirho)
            .unwrap()
            .len(),
        0
    );
    assert!(
        crate::app_chirho::verified_app_owner_chirho(&world_chirho.platform_chirho, "honest")
            .unwrap()
            .is_none(),
        "the honest intent is not applied either"
    );
    let _ = std::fs::remove_dir_all(&world_chirho.platform_chirho);
}

/// PFE gpt #21788/#21794: a form that derives its idempotency key from (kind, slug, version)
/// would deduplicate a FRESH approval after the live state changed, and an implicit lookup at
/// POST time could not tell that fresh approval from a delayed retry. So the form carries the
/// EXPLICIT approval base the status road rendered (`approval_base_chirho`), the attempt identity
/// is (principal, key, base), replay is answered first, and a new attempt whose base moved
/// refuses before any write. Ladder: publish v1 → republish v2 → roll back to v1 → republish v2
/// AGAIN with the same key → roll back to v1 AGAIN, double submits on each act, a delayed retry
/// after an intervening act, and a stale-base fresh approval.
#[test]
fn an_explicit_approval_base_separates_fresh_approvals_from_delayed_retries_chirho() {
    let world_chirho = world_chirho("approval-base");
    register_template_chirho(&world_chirho);
    let base_chirho = |world_chirho: &WorldChirho| -> (String, Option<HashChirho>) {
        let status_chirho: PublicationStatusResponseChirho = serde_json::from_slice(
            &status_read_chirho(
                world_chirho,
                PUBLICATION_CAPABILITY_PREFIX_CHIRHO,
                Some("good-earth-bakery"),
            )
            .unwrap(),
        )
        .unwrap();
        match status_chirho.slugs_chirho.first() {
            None => (DARK_PUBLICATION_BASE_CHIRHO.to_string(), None),
            Some(slug_chirho) => (
                slug_chirho.approval_base_chirho.clone(),
                slug_chirho
                    .live_chirho
                    .as_ref()
                    .map(|live_chirho| live_chirho.params_chirho.clone()),
            ),
        }
    };
    let form_chirho = |kind_chirho: &str,
                       key_chirho: &str,
                       title_chirho: Option<&str>,
                       prior_chirho: Option<&str>,
                       base_chirho: &str|
     -> Vec<u8> {
        let mut request_chirho: serde_json::Value =
            serde_json::from_slice(&publish_request_chirho(
                kind_chirho,
                "good-earth-bakery",
                key_chirho,
                title_chirho.map(page_chirho),
                prior_chirho,
                None,
            ))
            .unwrap();
        request_chirho["base_publication_chirho"] =
            serde_json::Value::String(base_chirho.to_string());
        serde_json::to_vec(&request_chirho).unwrap()
    };

    // publish v1 against the dark base; a double submit replays; the ticker applies it.
    let (dark_chirho, _) = base_chirho(&world_chirho);
    assert_eq!(dark_chirho, DARK_PUBLICATION_BASE_CHIRHO);
    let publish_v1_chirho = form_chirho(
        "publish-chirho",
        "k-publish",
        Some("v1"),
        None,
        &dark_chirho,
    );
    let v1_chirho = intend_ok_chirho(&world_chirho, &publish_v1_chirho);
    assert_eq!(
        intend_chirho(&world_chirho, &publish_v1_chirho).unwrap(),
        serde_json::to_vec(&v1_chirho).unwrap()
    );
    assert_eq!(apply_chirho(&world_chirho).applied_chirho, 1);
    let (base_v1_chirho, live_chirho) = base_chirho(&world_chirho);
    assert_eq!(base_v1_chirho, v1_chirho.intent_digest_chirho.0);
    assert_eq!(live_chirho, Some(v1_chirho.params_chirho.clone()));

    // A DELAYED retry of the publish form (its response was lost; the address already moved to
    // v1) replays the original receipt — same bytes, same base — and mints nothing.
    assert_eq!(
        intend_chirho(&world_chirho, &publish_v1_chirho).unwrap(),
        serde_json::to_vec(&v1_chirho).unwrap()
    );
    assert_eq!(
        verify_publication_intents_chirho(&world_chirho.tenant_chirho).unwrap(),
        1
    );

    // republish v2 against base v1; apply.
    let republish_v2_chirho = form_chirho(
        "republish-chirho",
        "k-republish-v2",
        Some("v2"),
        None,
        &base_v1_chirho,
    );
    let v2_chirho = intend_ok_chirho(&world_chirho, &republish_v2_chirho);
    assert_eq!(apply_chirho(&world_chirho).applied_chirho, 1);
    let (base_v2_chirho, live_chirho) = base_chirho(&world_chirho);
    assert_eq!(live_chirho, Some(v2_chirho.params_chirho.clone()));

    // roll back to v1 against base v2; apply.
    let rollback_chirho = form_chirho(
        "rollback-chirho",
        "k-rollback-v1",
        None,
        Some(&v1_chirho.params_chirho.0),
        &base_v2_chirho,
    );
    let back_one_chirho = intend_ok_chirho(&world_chirho, &rollback_chirho);
    assert_eq!(apply_chirho(&world_chirho).applied_chirho, 1);
    let (base_back_chirho, live_chirho) = base_chirho(&world_chirho);
    assert_eq!(live_chirho, Some(v1_chirho.params_chirho.clone()));

    // The STALE republish form (base v1, re-sent from an old tab) is not a retry of anything the
    // address still shows and not a fresh approval either: refused, nothing written.
    let stale_chirho = form_chirho(
        "republish-chirho",
        "k-stale",
        Some("v2"),
        None,
        &base_v1_chirho,
    );
    let refusal_chirho = intend_refused_chirho(&world_chirho, &stale_chirho);
    assert_eq!(refusal_chirho.refusal_code_chirho, "base-moved-chirho");
    assert_eq!(
        refusal_chirho.live_base_chirho.as_deref(),
        Some(base_back_chirho.as_str())
    );
    assert_eq!(
        verify_publication_intents_chirho(&world_chirho.tenant_chirho).unwrap(),
        3
    );

    // republish v2 AGAIN with the SAME key, rendered against the current base: a new attempt.
    let republish_again_chirho = form_chirho(
        "republish-chirho",
        "k-republish-v2",
        Some("v2"),
        None,
        &base_back_chirho,
    );
    let v2_again_chirho = intend_ok_chirho(&world_chirho, &republish_again_chirho);
    assert_ne!(
        v2_again_chirho.intent_digest_chirho,
        v2_chirho.intent_digest_chirho
    );
    assert_eq!(
        intend_chirho(&world_chirho, &republish_again_chirho).unwrap(),
        serde_json::to_vec(&v2_again_chirho).unwrap(),
        "its double submit replays"
    );
    assert_eq!(apply_chirho(&world_chirho).applied_chirho, 1);
    let (base_again_chirho, live_chirho) = base_chirho(&world_chirho);
    assert_eq!(live_chirho, Some(v2_chirho.params_chirho.clone()));

    // roll back to v1 AGAIN with the same key against the current base; apply; then a delayed
    // retry of THIS form replays it even though the address moved to its own outcome.
    let rollback_again_chirho = form_chirho(
        "rollback-chirho",
        "k-rollback-v1",
        None,
        Some(&v1_chirho.params_chirho.0),
        &base_again_chirho,
    );
    let back_two_chirho = intend_ok_chirho(&world_chirho, &rollback_again_chirho);
    assert_ne!(
        back_two_chirho.intent_digest_chirho,
        back_one_chirho.intent_digest_chirho
    );
    assert_eq!(apply_chirho(&world_chirho).applied_chirho, 1);
    assert_eq!(
        base_chirho(&world_chirho).1,
        Some(v1_chirho.params_chirho.clone())
    );
    assert_eq!(
        intend_chirho(&world_chirho, &rollback_again_chirho).unwrap(),
        serde_json::to_vec(&back_two_chirho).unwrap()
    );
    assert_eq!(
        verify_publication_intents_chirho(&world_chirho.tenant_chirho).unwrap(),
        5
    );
    assert_eq!(apply_chirho(&world_chirho).applied_chirho, 0);
    let _ = std::fs::remove_dir_all(&world_chirho.platform_chirho);
}

/// PFE gpt #21797, the sharpest form: a delayed retry of "roll back to v1" that arrives AFTER a
/// later intentional publish of v3 must replay its original receipt — no new intent, no quota
/// charge, v3 stays live. Under the explicit approval base the retry carries the base it was
/// approved against, so it is the recorded attempt, answered before admission and before the
/// base check ever runs.
#[test]
fn a_delayed_rollback_retry_after_a_newer_publication_replays_and_leaves_v3_live_chirho() {
    let world_chirho = world_chirho("delayed-rollback-retry");
    register_template_chirho(&world_chirho);
    let form_chirho = |kind_chirho: &str,
                       key_chirho: &str,
                       title_chirho: Option<&str>,
                       prior_chirho: Option<&str>,
                       base_chirho: &str|
     -> Vec<u8> {
        let mut request_chirho: serde_json::Value =
            serde_json::from_slice(&publish_request_chirho(
                kind_chirho,
                "good-earth-bakery",
                key_chirho,
                title_chirho.map(page_chirho),
                prior_chirho,
                None,
            ))
            .unwrap();
        request_chirho["base_publication_chirho"] =
            serde_json::Value::String(base_chirho.to_string());
        serde_json::to_vec(&request_chirho).unwrap()
    };
    let live_params_chirho = |world_chirho: &WorldChirho| -> HashChirho {
        let status_chirho: PublicationStatusResponseChirho = serde_json::from_slice(
            &status_read_chirho(
                world_chirho,
                PUBLICATION_CAPABILITY_PREFIX_CHIRHO,
                Some("good-earth-bakery"),
            )
            .unwrap(),
        )
        .unwrap();
        status_chirho.slugs_chirho[0]
            .live_chirho
            .clone()
            .expect("live")
            .params_chirho
    };
    let v1_chirho = intend_ok_chirho(
        &world_chirho,
        &form_chirho(
            "publish-chirho",
            "k1",
            Some("v1"),
            None,
            DARK_PUBLICATION_BASE_CHIRHO,
        ),
    );
    assert_eq!(apply_chirho(&world_chirho).applied_chirho, 1);
    let v2_chirho = intend_ok_chirho(
        &world_chirho,
        &form_chirho(
            "republish-chirho",
            "k2",
            Some("v2"),
            None,
            &v1_chirho.intent_digest_chirho.0,
        ),
    );
    assert_eq!(apply_chirho(&world_chirho).applied_chirho, 1);
    let rollback_form_chirho = form_chirho(
        "rollback-chirho",
        "k-rollback",
        None,
        Some(&v1_chirho.params_chirho.0),
        &v2_chirho.intent_digest_chirho.0,
    );
    let rollback_chirho = intend_ok_chirho(&world_chirho, &rollback_form_chirho);
    assert_eq!(apply_chirho(&world_chirho).applied_chirho, 1);
    assert_eq!(live_params_chirho(&world_chirho), v1_chirho.params_chirho);
    // A later INTENTIONAL publish of v3, approved against the rollback's base.
    let v3_chirho = intend_ok_chirho(
        &world_chirho,
        &form_chirho(
            "republish-chirho",
            "k3",
            Some("v3"),
            None,
            &rollback_chirho.intent_digest_chirho.0,
        ),
    );
    assert_eq!(apply_chirho(&world_chirho).applied_chirho, 1);
    assert_eq!(live_params_chirho(&world_chirho), v3_chirho.params_chirho);

    let intents_before_chirho =
        verify_publication_intents_chirho(&world_chirho.tenant_chirho).unwrap();
    let usage_before_chirho =
        resource_chirho::load_resource_usage_chirho(&world_chirho.tenant_chirho)
            .unwrap()
            .len();
    // The delayed retry of the rollback form: identical bytes, the base it was approved against.
    assert_eq!(
        intend_chirho(&world_chirho, &rollback_form_chirho).unwrap(),
        serde_json::to_vec(&rollback_chirho).unwrap(),
        "the original receipt, byte for byte"
    );
    assert_eq!(
        verify_publication_intents_chirho(&world_chirho.tenant_chirho).unwrap(),
        intents_before_chirho,
        "no new intent"
    );
    assert_eq!(
        resource_chirho::load_resource_usage_chirho(&world_chirho.tenant_chirho)
            .unwrap()
            .len(),
        usage_before_chirho,
        "no quota charge"
    );
    assert_eq!(apply_chirho(&world_chirho).applied_chirho, 0);
    assert_eq!(
        live_params_chirho(&world_chirho),
        v3_chirho.params_chirho,
        "v3 stays live"
    );
    let _ = std::fs::remove_dir_all(&world_chirho.platform_chirho);
}

/// claude2 #21816: the descriptor-v2 check in `judge_chirho` is the only gate between "registered"
/// and "deployable" on this road, and nothing downstream re-verifies. A template that IS in the
/// verified registry but whose root DAG is not deployable (an effect node with no undo-plan
/// bindings) refuses with its own token and deploys nothing to the public platform root; deleting
/// the check turns this arm red because the applier would deploy the effectful DAG.
#[test]
fn a_registered_template_that_is_not_deployable_refuses_and_deploys_nothing_chirho() {
    let world_chirho = world_chirho("template-not-deployable");
    let schema_chirho = cas_chirho::add_chirho(&world_chirho.platform_chirho, b"bytes").unwrap();
    let effect_node_chirho = crate::model_chirho::NodeDefChirho {
        name_chirho: "write_store_chirho".to_string(),
        impl_wasm_chirho: cas_chirho::add_chirho(
            &world_chirho.platform_chirho,
            b"builtin:write-store-chirho",
        )
        .unwrap(),
        entry_chirho: "write_store_chirho".to_string(),
        inputs_chirho: vec![crate::model_chirho::PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: schema_chirho.clone(),
        }],
        outputs_chirho: vec![crate::model_chirho::PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho,
        }],
        capabilities_chirho: vec![CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "landing-chirho/".to_string(),
        }],
        fuel_limit_chirho: 0,
        ..Default::default()
    };
    let node_hash_chirho =
        store_chirho::put_object_chirho(&world_chirho.platform_chirho, &effect_node_chirho)
            .unwrap();
    let effectful_dag_chirho = store_chirho::put_object_chirho(
        &world_chirho.platform_chirho,
        &DagChirho {
            nodes_chirho: vec![node_hash_chirho],
            edges_chirho: vec![],
        },
    )
    .unwrap();
    let template_id_chirho = "effectful-template-chirho";
    crate::app_chirho::register_template_app_template_chirho(
        &world_chirho.platform_chirho,
        crate::app_chirho::TemplateRegistryInputChirho {
            template_id_chirho: template_id_chirho.to_string(),
            root_dag_chirho: effectful_dag_chirho.clone(),
            response_content_type_chirho: "text/html".to_string(),
        },
    )
    .unwrap();
    // Positive control on the fixture: the template IS registered and IS what the judge looks up,
    // and the descriptor boundary itself refuses that DAG.
    let registry_chirho =
        crate::app_chirho::verified_template_registry_chirho(&world_chirho.platform_chirho)
            .unwrap();
    assert_eq!(
        registry_chirho
            .get(template_id_chirho)
            .map(|template_chirho| template_chirho.root_dag_chirho.clone()),
        Some(effectful_dag_chirho.clone())
    );
    assert!(
        crate::app_source_manifest_chirho::verify_descriptor_v2_deployment_chirho(
            &world_chirho.platform_chirho,
            &std::collections::BTreeSet::from([effectful_dag_chirho]),
            None,
        )
        .is_err()
    );

    let response_chirho: PublicationIntentResponseChirho = serde_json::from_slice(
        &crate::app_chirho::run_template_app_deploy_effect_chirho(
            &world_chirho.tenant_chirho,
            template_id_chirho,
            &publish_request_chirho(
                "publish-chirho",
                "effectful-slug",
                "attempt-effectful",
                Some(page_chirho("Effectful")),
                None,
                None,
            ),
            Some(&world_chirho.context_chirho),
        )
        .expect("the tenant door records the intent; the platform judges deployability"),
    )
    .unwrap();
    let report_chirho = apply_chirho(&world_chirho);
    assert_eq!(
        (report_chirho.applied_chirho, report_chirho.refused_chirho),
        (0, 1),
        "{report_chirho:?}"
    );
    assert_eq!(
        report_chirho
            .refusals_chirho
            .get("template-not-deployable-chirho"),
        Some(&1),
        "refused for deployability, not for registry membership: {report_chirho:?}"
    );
    assert!(
        crate::app_chirho::verified_app_owner_chirho(
            &world_chirho.platform_chirho,
            "effectful-slug"
        )
        .unwrap()
        .is_none(),
        "nothing was deployed to the public platform root"
    );
    let applied_chirho =
        load_verified_publication_applied_chirho(&world_chirho.platform_chirho).unwrap();
    assert_eq!(applied_chirho.len(), 1);
    assert_eq!(
        applied_chirho[0].intent_digest_chirho,
        response_chirho.intent_digest_chirho
    );
    assert_eq!(
        applied_chirho[0].refusal_code_chirho.as_deref(),
        Some("template-not-deployable-chirho")
    );
    let _ = std::fs::remove_dir_all(&world_chirho.platform_chirho);
}
