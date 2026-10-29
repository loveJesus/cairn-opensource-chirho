// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The occupied-name (`slug-taken-chirho`) door refusal (CAIRN #24144 / SHAPE 2, Model B): the
//! publication intent door decides occupancy against the platform's canonical ownership model —
//! verified slug CLAIMS and deployed-app ownership — READ-ONLY and PRE-ADMISSION, refusing a name a
//! different account already holds WITHOUT echoing that account's live digest, minting an owner or
//! key, or charging her allowance. The door and the applier reach that decision through one shared
//! function, so they refuse the same names. Covers gpt #24599's arm matrix, the single-fenced
//! no-leak boundary (mutation-proven), and the custody invariant (public-key-only discriminator).

use super::apply_chirho::{
    apply_publication_intents_chirho, load_verified_publication_owners_chirho,
    load_verified_slug_claims_chirho, slug_occupancy_for_requester_chirho, SlugOccupancyChirho,
};
use super::status_chirho::{
    live_identity_for_slug_for_viewer_chirho, DARK_PUBLICATION_BASE_CHIRHO,
};
use super::tests_chirho::{
    charged_publication_units_chirho, head_binding_chirho, intend_chirho, intend_refused_chirho,
    page_chirho, publish_request_chirho, save_version_chirho, saved_page_bytes_chirho,
    tmp_platform_root_chirho, world_chirho, WorldChirho, TEMPLATE_CHIRHO,
};
use super::*;
use crate::model_chirho::DagChirho;
use std::path::Path;

const TENANT_LABEL_CHIRHO: &str = "beta-chirho";
const PRIVATE_KEY_FILE_CHIRHO: &str = "signing-key-chirho.bin";
const PUBLIC_KEY_FILE_CHIRHO: &str = "pubkey-chirho.hex";

// ---- fixtures -----------------------------------------------------------------------------------

/// A second signed-in viewer of the SAME tenant (a distinct user digest, hence a distinct platform
/// owner), so one viewer can hold a name the other tries to take.
fn co_tenant_world_chirho(base_chirho: &WorldChirho) -> WorldChirho {
    let user_chirho = identity_chirho::register_identity_chirho(
        &base_chirho.tenant_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
    )
    .unwrap()
    .principal_chirho;
    let mut world_chirho = WorldChirho {
        platform_chirho: base_chirho.platform_chirho.clone(),
        tenant_chirho: base_chirho.tenant_chirho.clone(),
        context_chirho: base_chirho.context_chirho.clone(),
    };
    world_chirho.context_chirho.user_principal_chirho = user_chirho;
    world_chirho
}

fn empty_dag_chirho(root_chirho: &Path) -> HashChirho {
    store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: Vec::new(),
            edges_chirho: Vec::new(),
        },
    )
    .unwrap()
}

/// Register the page template on the PLATFORM root, as the operator does, so the applier can judge
/// and deploy a publish.
fn register_platform_template_chirho(platform_chirho: &Path) {
    let dag_chirho = empty_dag_chirho(platform_chirho);
    crate::app_chirho::register_template_app_template_chirho(
        platform_chirho,
        crate::app_chirho::TemplateRegistryInputChirho {
            template_id_chirho: TEMPLATE_CHIRHO.to_string(),
            root_dag_chirho: dag_chirho,
            response_content_type_chirho: "text/html".to_string(),
        },
    )
    .unwrap();
}

/// The holder publishes a fresh inline document to `slug` and the applier lands it, so the platform
/// now carries her signed claim, her deployed app, and one applied live record for the slug.
fn hold_slug_via_publish_chirho(holder_chirho: &WorldChirho, slug_chirho: &str, idem_chirho: &str) {
    intend_chirho(
        holder_chirho,
        &publish_request_chirho(
            "publish-chirho",
            slug_chirho,
            idem_chirho,
            Some(page_chirho("Holder page")),
            None,
            None,
        ),
    )
    .expect("the holder's fresh publish is admitted (the slug is free for her)");
    let report_chirho =
        apply_publication_intents_chirho(&holder_chirho.platform_chirho, TENANT_LABEL_CHIRHO)
            .expect("apply runs");
    assert_eq!(report_chirho.applied_chirho, 1, "{report_chirho:?}");
}

/// Deploy an app DIRECTLY on the platform root under a foreign owner — a valid unreserved platform
/// app with NO publication claim and NO applied record — and return that foreign owner principal.
fn deploy_foreign_platform_app_chirho(platform_chirho: &Path, slug_chirho: &str) -> String {
    let foreign_owner_chirho = identity_chirho::register_identity_chirho(
        platform_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let dag_chirho = empty_dag_chirho(platform_chirho);
    crate::app_chirho::deploy_app_chirho(
        platform_chirho,
        slug_chirho,
        dag_chirho,
        &foreign_owner_chirho,
    )
    .unwrap();
    foreign_owner_chirho
}

/// The slug's live applied digest as ANY holder sees it — exactly what the pre-fix unscoped
/// `live_identity_for_slug_chirho` would have echoed to a foreign requester. Used to prove that
/// digest is absent from the occupied refusal.
fn foreign_live_digest_chirho(platform_chirho: &Path, slug_chirho: &str) -> String {
    load_verified_publication_applied_chirho(platform_chirho)
        .unwrap()
        .into_iter()
        .rev()
        .find(|record_chirho| {
            record_chirho.slug_chirho == slug_chirho
                && record_chirho.outcome_chirho == PublicationOutcomeChirho::AppliedChirho
                && record_chirho.params_record_seq_chirho.is_some()
        })
        .map(|record_chirho| record_chirho.intent_digest_chirho.0)
        .expect("the holder has an applied live digest")
}

fn refusal_of_chirho(bytes_chirho: &[u8]) -> PublicationIntentRefusalChirho {
    serde_json::from_slice(bytes_chirho).expect("a typed door refusal")
}

fn assert_admitted_chirho(bytes_chirho: &[u8], context_chirho: &str) {
    let value_chirho: serde_json::Value = serde_json::from_slice(bytes_chirho).unwrap();
    assert_eq!(
        value_chirho["schema_chirho"],
        serde_json::json!(PUBLICATION_INTENT_RESPONSE_SCHEMA_CHIRHO),
        "expected an admitted intent {context_chirho}, got {value_chirho}"
    );
}

fn contains_bytes_chirho(haystack_chirho: &[u8], needle_chirho: &str) -> bool {
    let needle_chirho = needle_chirho.as_bytes();
    !needle_chirho.is_empty()
        && haystack_chirho
            .windows(needle_chirho.len())
            .any(|window_chirho| window_chirho == needle_chirho)
}

fn count_owners_chirho(platform_chirho: &Path) -> usize {
    load_verified_publication_owners_chirho(platform_chirho)
        .unwrap()
        .len()
}

fn count_applied_chirho(platform_chirho: &Path) -> usize {
    load_verified_publication_applied_chirho(platform_chirho)
        .unwrap()
        .len()
}

// ---- arm matrix (gpt #24599) --------------------------------------------------------------------

/// Foreign CLAIM / foreign LIVE publication: one viewer holds a slug end-to-end; a co-tenant viewer
/// is refused `slug-taken-chirho` at the door. Positive controls: her OWN held slug (republish) and
/// a FREE slug both proceed.
#[test]
fn a_foreign_holder_is_refused_slug_taken_while_own_and_free_slugs_proceed_chirho() {
    let world_chirho = world_chirho("occupied-foreign-holder");
    register_platform_template_chirho(&world_chirho.platform_chirho);

    // A (co-tenant) holds "held-by-a" via a full publish + apply.
    let holder_chirho = co_tenant_world_chirho(&world_chirho);
    hold_slug_via_publish_chirho(&holder_chirho, "held-by-a", "a1");

    // B (the base viewer) is refused the name A holds — a foreign claim AND a foreign live app.
    let refusal_chirho = intend_refused_chirho(
        &world_chirho,
        &publish_request_chirho(
            "publish-chirho",
            "held-by-a",
            "b1",
            Some(page_chirho("B tries")),
            None,
            None,
        ),
    );
    assert_eq!(refusal_chirho.refusal_code_chirho, "slug-taken-chirho");

    // Positive control 1 — a FREE slug: B publishes an unclaimed name and the door admits it.
    assert_admitted_chirho(
        &intend_chirho(
            &world_chirho,
            &publish_request_chirho(
                "publish-chirho",
                "free-for-b",
                "b2",
                Some(page_chirho("B free")),
                None,
                None,
            ),
        )
        .expect("the door answers"),
        "on a free slug",
    );

    // Positive control 2 — HER OWN slug: A applies "free-for-b"? no — A republishes what she holds.
    assert_admitted_chirho(
        &intend_chirho(
            &holder_chirho,
            &publish_request_chirho(
                "republish-chirho",
                "held-by-a",
                "a2",
                Some(page_chirho("A again")),
                None,
                None,
            ),
        )
        .expect("the door answers"),
        "on her own held slug",
    );
}

/// The case Model A (viewer-scope the applied scan) MISSED: an unreserved platform app owned by a
/// foreign account, with NO claim and NO applied publication record. The door still refuses
/// `slug-taken-chirho`, and the viewer-scoped applied base — which is all Model A would have
/// checked — is `dark-chirho`, so a base check alone would have admitted a doomed attempt.
#[test]
fn an_unreserved_foreign_app_owner_with_no_publication_history_is_refused_chirho() {
    let world_chirho = world_chirho("occupied-app-only");
    register_platform_template_chirho(&world_chirho.platform_chirho);
    deploy_foreign_platform_app_chirho(&world_chirho.platform_chirho, "app-only-slug");

    // Model A's only signal is dark here — proof the applied scan cannot see this occupancy.
    let user_digest_chirho =
        publication_user_digest_chirho(&world_chirho.context_chirho.user_principal_chirho);
    assert_eq!(
        live_identity_for_slug_for_viewer_chirho(
            &world_chirho.tenant_chirho,
            "app-only-slug",
            &user_digest_chirho,
            TENANT_LABEL_CHIRHO,
        )
        .unwrap(),
        DARK_PUBLICATION_BASE_CHIRHO,
        "no applied record exists, so a base check alone would admit"
    );

    // Model B refuses it at the door on the deployed-app ownership.
    let refusal_chirho = intend_refused_chirho(
        &world_chirho,
        &publish_request_chirho(
            "publish-chirho",
            "app-only-slug",
            "b1",
            Some(page_chirho("B tries")),
            None,
            None,
        ),
    );
    assert_eq!(refusal_chirho.refusal_code_chirho, "slug-taken-chirho");
    assert_eq!(refusal_chirho.slug_chirho.as_deref(), Some("app-only-slug"));
    assert_eq!(refusal_chirho.live_base_chirho, None);
}

/// Unconditional: an occupied slug is refused whether the form carries NO base at all or an explicit
/// `dark-chirho` base — occupancy is resolved before the base comparison, so neither shape slips
/// through, and neither is written.
#[test]
fn an_occupied_slug_is_refused_baseless_and_with_an_explicit_dark_base_chirho() {
    let world_chirho = world_chirho("occupied-unconditional");
    register_platform_template_chirho(&world_chirho.platform_chirho);
    let holder_chirho = co_tenant_world_chirho(&world_chirho);
    hold_slug_via_publish_chirho(&holder_chirho, "held-by-a", "a1");

    // Base-less.
    assert_eq!(
        intend_refused_chirho(
            &world_chirho,
            &publish_request_chirho(
                "publish-chirho",
                "held-by-a",
                "b1",
                Some(page_chirho("B tries")),
                None,
                None,
            ),
        )
        .refusal_code_chirho,
        "slug-taken-chirho"
    );

    // Explicit dark base — occupancy fires BEFORE the base comparison, so even a dark base refuses.
    let dark_base_request_chirho = {
        let mut value_chirho: serde_json::Value = serde_json::from_slice(&publish_request_chirho(
            "publish-chirho",
            "held-by-a",
            "b2",
            Some(page_chirho("B tries dark")),
            None,
            None,
        ))
        .unwrap();
        value_chirho["base_publication_chirho"] =
            serde_json::Value::String(DARK_PUBLICATION_BASE_CHIRHO.to_string());
        serde_json::to_vec(&value_chirho).unwrap()
    };
    assert_eq!(
        intend_refused_chirho(&world_chirho, &dark_base_request_chirho).refusal_code_chirho,
        "slug-taken-chirho"
    );

    // Nothing new was written for B on either attempt.
    assert_eq!(
        load_verified_publication_applied_chirho(&world_chirho.platform_chirho)
            .unwrap()
            .iter()
            .filter(|record_chirho| record_chirho.tenant_chirho == TENANT_LABEL_CHIRHO)
            .count(),
        1,
        "only A's one applied record exists"
    );
}

// ---- the wire + the single-fenced no-leak boundary ----------------------------------------------

/// The wire (PFE Option A) and the no-leak fence, single-fenced at the door and MUTATION-PROVEN: the
/// occupied refusal carries her OWN validated slug and her OWN verified head version (> 0), and its
/// serialized ENGINE DOOR RESULT (the bytes the door effect returns, before any renderer) carries
/// `live_base_chirho == None` with ZERO bytes of the foreign holder's live digest. A positive
/// control on the real serialization path proves the digest WOULD be found if the door emitted it.
#[test]
fn the_occupied_refusal_carries_her_wire_and_leaks_no_foreign_digest_chirho() {
    let world_chirho = world_chirho("occupied-no-leak");
    register_platform_template_chirho(&world_chirho.platform_chirho);
    let holder_chirho = co_tenant_world_chirho(&world_chirho);
    hold_slug_via_publish_chirho(&holder_chirho, "held-by-a", "a1");
    let foreign_digest_chirho =
        foreign_live_digest_chirho(&world_chirho.platform_chirho, "held-by-a");
    assert_eq!(foreign_digest_chirho.len(), 64, "a real 32-byte hex digest");

    // Two saved versions: her verified head is version 2. She then submits a binding that CLAIMS a
    // wrong version, and the door must state her VERIFIED head (2), never the submitted number — a
    // version the page did not get from the door is never presented as current (criterion 4).
    save_version_chirho(&world_chirho, None, &saved_page_bytes_chirho("B page v1"));
    save_version_chirho(
        &world_chirho,
        Some(1),
        &saved_page_bytes_chirho("B page v2"),
    );
    let binding_chirho = head_binding_chirho(&world_chirho);
    assert_eq!(
        binding_chirho.version_chirho, 2,
        "her verified head is version 2"
    );
    let mut wrong_version_binding_chirho = binding_chirho.clone();
    wrong_version_binding_chirho.version_chirho = 99;

    let door_bytes_chirho = intend_chirho(
        &world_chirho,
        &publish_request_chirho(
            "publish-chirho",
            "held-by-a",
            "b1",
            None,
            None,
            Some(&wrong_version_binding_chirho),
        ),
    )
    .expect("the door answers, typed");

    let refusal_chirho = refusal_of_chirho(&door_bytes_chirho);
    assert_eq!(
        refusal_chirho.schema_chirho,
        PUBLICATION_INTENT_REFUSAL_SCHEMA_CHIRHO
    );
    assert_eq!(refusal_chirho.refusal_code_chirho, "slug-taken-chirho");
    assert_eq!(
        refusal_chirho.slug_chirho.as_deref(),
        Some("held-by-a"),
        "her own re-validated submitted name is echoed back"
    );
    assert_eq!(
        refusal_chirho.head_version_chirho,
        Some(binding_chirho.version_chirho),
        "her VERIFIED head version (2), read from her head — not the submitted 99"
    );
    assert_ne!(
        refusal_chirho.head_version_chirho,
        Some(99),
        "the submitted version is never presented as current"
    );
    assert!(refusal_chirho.head_version_chirho.unwrap() > 0);
    assert_eq!(
        refusal_chirho.live_base_chirho, None,
        "FENCE: the occupied refusal carries no foreign digest"
    );

    // The single fence, byte level: the foreign holder's live digest is nowhere in the door result.
    assert!(
        !contains_bytes_chirho(&door_bytes_chirho, &foreign_digest_chirho),
        "the foreign live digest must not appear anywhere in the door result"
    );

    // Positive control — the search instrument is attributing: the SAME serialization path with the
    // digest deliberately present is found, so the absence above is real, not a broken search.
    let leaky_bytes_chirho = serde_json::to_vec(&PublicationIntentRefusalChirho {
        schema_chirho: PUBLICATION_INTENT_REFUSAL_SCHEMA_CHIRHO.to_string(),
        refusal_code_chirho: "slug-taken-chirho".to_string(),
        message_chirho: "control".to_string(),
        live_base_chirho: Some(foreign_digest_chirho.clone()),
        head_version_chirho: refusal_chirho.head_version_chirho,
        slug_chirho: Some("held-by-a".to_string()),
    })
    .unwrap();
    assert!(
        contains_bytes_chirho(&leaky_bytes_chirho, &foreign_digest_chirho),
        "positive control: a leaked digest IS found by the same search, so the fence assertion bites"
    );
}

// ---- the money-authority / custody invariant ----------------------------------------------------

/// The pre-admission money/custody property: a foreign-slug refusal mints NO platform owner, writes
/// NO intent and NO applied record, and charges NO publication unit — the viewer's allowance and the
/// platform's owner/applied logs are byte-for-byte where they were. Fresh payloads and a real quota
/// make the unchanged counters discriminating.
#[test]
fn a_foreign_slug_refusal_mints_no_owner_and_charges_nothing_chirho() {
    let world_chirho = world_chirho("occupied-no-spend");
    register_platform_template_chirho(&world_chirho.platform_chirho);
    let holder_chirho = co_tenant_world_chirho(&world_chirho);
    hold_slug_via_publish_chirho(&holder_chirho, "held-by-a", "a1");

    // B has a real recovery-form submission (a saved version + binding) and a live quota.
    save_version_chirho(&world_chirho, None, &saved_page_bytes_chirho("B page"));
    let binding_chirho = head_binding_chirho(&world_chirho);

    let owners_before_chirho = count_owners_chirho(&world_chirho.platform_chirho);
    let applied_before_chirho = count_applied_chirho(&world_chirho.platform_chirho);
    let charged_before_chirho = charged_publication_units_chirho(&world_chirho);
    let intents_before_chirho =
        verify_publication_intents_chirho(&world_chirho.tenant_chirho).unwrap();

    let refusal_chirho = intend_refused_chirho(
        &world_chirho,
        &publish_request_chirho(
            "publish-chirho",
            "held-by-a",
            "b-fresh",
            None,
            None,
            Some(&binding_chirho),
        ),
    );
    assert_eq!(refusal_chirho.refusal_code_chirho, "slug-taken-chirho");

    assert_eq!(
        count_owners_chirho(&world_chirho.platform_chirho),
        owners_before_chirho,
        "no platform owner is minted for a refused occupied name"
    );
    assert_eq!(
        count_applied_chirho(&world_chirho.platform_chirho),
        applied_before_chirho,
        "no applied record is written"
    );
    assert_eq!(
        charged_publication_units_chirho(&world_chirho),
        charged_before_chirho,
        "no publication allowance is consumed (pre-admission refusal)"
    );
    assert_eq!(
        verify_publication_intents_chirho(&world_chirho.tenant_chirho).unwrap(),
        intents_before_chirho,
        "no intent is recorded"
    );
}

/// The custody discriminator: the door's occupancy read path reads only the EXISTING public key and
/// never mints or rewrites a signing key. With the platform PRIVATE key removed (public key only),
/// a foreign-slug refusal still works, the private key stays absent, and the public key bytes are
/// untouched. Two mint timings are caught two different ways (gpt #24641), and both protections are
/// load-bearing: an EARLY getter revert (a loader back on `pubkey_hex_chirho`) mints a new key that
/// overwrites the public key and invalidates existing-record signatures, so it fails UPSTREAM at
/// signature verification (inside `intend_refused_chirho`) before the filesystem assertions below run;
/// a LATE mint (after the head read, before the refusal returns) yields the typed refusal and is
/// caught HERE by the filesystem assertions (:525). Keep both.
#[test]
fn the_occupancy_read_path_reads_only_the_existing_public_key_chirho() {
    let world_chirho = world_chirho("occupied-custody");
    register_platform_template_chirho(&world_chirho.platform_chirho);
    let holder_chirho = co_tenant_world_chirho(&world_chirho);
    hold_slug_via_publish_chirho(&holder_chirho, "held-by-a", "a1");

    let private_key_chirho = world_chirho.platform_chirho.join(PRIVATE_KEY_FILE_CHIRHO);
    let public_key_chirho = world_chirho.platform_chirho.join(PUBLIC_KEY_FILE_CHIRHO);
    assert!(
        private_key_chirho.exists(),
        "the holder's apply created the platform key"
    );
    let public_before_chirho = std::fs::read(&public_key_chirho).unwrap();

    // Strip the private key: a read/refusal path must not need it, and must not re-create it.
    std::fs::remove_file(&private_key_chirho).unwrap();

    let refusal_chirho = intend_refused_chirho(
        &world_chirho,
        &publish_request_chirho(
            "publish-chirho",
            "held-by-a",
            "b1",
            Some(page_chirho("B tries")),
            None,
            None,
        ),
    );
    assert_eq!(
        refusal_chirho.refusal_code_chirho, "slug-taken-chirho",
        "the door refuses on the existing public key alone"
    );
    assert!(
        !private_key_chirho.exists(),
        "the occupancy read path must not mint a private signing key"
    );
    assert_eq!(
        std::fs::read(&public_key_chirho).unwrap(),
        public_before_chirho,
        "the public key bytes are untouched (no key rotation on a read path)"
    );
}

/// Empty-history preservation: the three verified loaders return an empty history on a bare root
/// WITHOUT reading — and therefore without minting — any signing key. Removing the empty guard would
/// either fail closed on `existing_pubkey_hex_chirho` (an unreadable key) or, with the old
/// `pubkey_hex_chirho`, mint one; both would redden this.
#[test]
fn empty_publication_histories_verify_without_minting_a_key_chirho() {
    let root_chirho = tmp_platform_root_chirho("occupied-empty-history");
    assert!(load_verified_publication_owners_chirho(&root_chirho)
        .unwrap()
        .is_empty());
    assert!(load_verified_slug_claims_chirho(&root_chirho)
        .unwrap()
        .is_empty());
    assert!(load_verified_publication_applied_chirho(&root_chirho)
        .unwrap()
        .is_empty());
    assert!(
        !root_chirho.join(PRIVATE_KEY_FILE_CHIRHO).exists()
            && !root_chirho.join(PUBLIC_KEY_FILE_CHIRHO).exists(),
        "an empty history needs no key and must not create one"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

// ---- door and applier agree by construction -----------------------------------------------------

/// The shared decision: `slug_occupancy_for_requester_chirho` reports OccupiedByAnother for the
/// exact (tenant, user_digest) the door refuses, Available (with the right claim/app flags) for a
/// free slug and for the holder herself — so the door and the applier's `judge_chirho`, which both
/// route through it, cannot drift apart.
#[test]
fn the_shared_occupancy_decision_matches_holder_requester_and_free_chirho() {
    let world_chirho = world_chirho("occupied-shared-decision");
    register_platform_template_chirho(&world_chirho.platform_chirho);
    let holder_chirho = co_tenant_world_chirho(&world_chirho);
    hold_slug_via_publish_chirho(&holder_chirho, "held-by-a", "a1");

    let requester_digest_chirho =
        publication_user_digest_chirho(&world_chirho.context_chirho.user_principal_chirho);
    let holder_digest_chirho =
        publication_user_digest_chirho(&holder_chirho.context_chirho.user_principal_chirho);

    // A foreign requester: occupied.
    assert!(matches!(
        slug_occupancy_for_requester_chirho(
            &world_chirho.platform_chirho,
            "held-by-a",
            TENANT_LABEL_CHIRHO,
            &requester_digest_chirho,
        )
        .unwrap(),
        SlugOccupancyChirho::OccupiedByAnotherChirho
    ));

    // The holder herself: available, with her claim AND her deployed app present.
    assert!(matches!(
        slug_occupancy_for_requester_chirho(
            &world_chirho.platform_chirho,
            "held-by-a",
            TENANT_LABEL_CHIRHO,
            &holder_digest_chirho,
        )
        .unwrap(),
        SlugOccupancyChirho::AvailableToRequesterChirho {
            claim_exists_chirho: true,
            app_exists_chirho: true,
        }
    ));

    // A free slug: available to anyone, nothing held.
    assert!(matches!(
        slug_occupancy_for_requester_chirho(
            &world_chirho.platform_chirho,
            "nobody-holds-this",
            TENANT_LABEL_CHIRHO,
            &requester_digest_chirho,
        )
        .unwrap(),
        SlugOccupancyChirho::AvailableToRequesterChirho {
            claim_exists_chirho: false,
            app_exists_chirho: false,
        }
    ));
}

fn audit_refusal_keeps_document_private_chirho(bound_chirho: bool) {
    let world_chirho = world_chirho(if bound_chirho {
        "audit-occupied-bound-cas-chirho"
    } else {
        "audit-occupied-inline-cas-chirho"
    });
    deploy_foreign_platform_app_chirho(&world_chirho.platform_chirho, "audit-held-chirho");
    let document_chirho = page_chirho("Independent private CAS witness chirho");
    let hash_chirho = store_chirho::hash_object_chirho(&document_chirho).unwrap();
    let binding_chirho = if bound_chirho {
        save_version_chirho(
            &world_chirho,
            None,
            &saved_page_bytes_chirho("Independent private CAS witness chirho"),
        );
        Some(head_binding_chirho(&world_chirho))
    } else {
        None
    };
    assert!(cas_chirho::get_chirho(&world_chirho.tenant_chirho, &hash_chirho).is_err());
    let refusal_chirho = intend_refused_chirho(
        &world_chirho,
        &publish_request_chirho(
            "publish-chirho",
            "audit-held-chirho",
            "audit-refusal-chirho",
            (!bound_chirho).then(|| document_chirho.clone()),
            None,
            binding_chirho.as_ref(),
        ),
    );
    assert_eq!(refusal_chirho.refusal_code_chirho, "slug-taken-chirho");
    assert!(
        cas_chirho::get_chirho(&world_chirho.tenant_chirho, &hash_chirho).is_err(),
        "occupied refusal published private document {hash_chirho:?} (bound={bound_chirho})"
    );

    let admitted_chirho = intend_chirho(
        &world_chirho,
        &publish_request_chirho(
            "publish-chirho",
            "audit-free-chirho",
            "audit-control-chirho",
            (!bound_chirho).then(|| document_chirho.clone()),
            None,
            binding_chirho.as_ref(),
        ),
    )
    .unwrap();
    assert_admitted_chirho(&admitted_chirho, "same document on an available slug");
    let public_chirho: serde_json::Value =
        store_chirho::get_object_chirho(&world_chirho.tenant_chirho, &hash_chirho).unwrap();
    assert_eq!(
        public_chirho, document_chirho,
        "CAS witness positive control"
    );
    std::fs::remove_dir_all(&world_chirho.platform_chirho).unwrap();
}

#[test]
fn audit_occupied_inline_input_never_reaches_public_cas_chirho() {
    audit_refusal_keeps_document_private_chirho(false);
}

#[test]
fn audit_occupied_saved_input_never_reaches_public_cas_chirho() {
    audit_refusal_keeps_document_private_chirho(true);
}

#[test]
fn audit_applied_base_ignores_foreign_viewers_and_tenants_chirho() {
    let world_chirho = world_chirho("audit-viewer-base-chirho");
    let viewer_chirho =
        publication_user_digest_chirho(&world_chirho.context_chirho.user_principal_chirho);
    let own_digest_chirho = HashChirho("a1".repeat(32));
    for (tenant_chirho, user_chirho, digest_chirho) in [
        (
            TENANT_LABEL_CHIRHO,
            viewer_chirho.clone(),
            own_digest_chirho.clone(),
        ),
        (
            TENANT_LABEL_CHIRHO,
            publication_user_digest_chirho("user/another-chirho"),
            HashChirho("b2".repeat(32)),
        ),
        (
            "other-tenant-chirho",
            viewer_chirho.clone(),
            HashChirho("c3".repeat(32)),
        ),
    ] {
        append_publication_applied_record_chirho(
            &world_chirho.platform_chirho,
            PublicationAppliedInputChirho {
                tenant_chirho: tenant_chirho.to_string(),
                intent_digest_chirho: digest_chirho,
                user_digest_chirho: user_chirho,
                kind_chirho: PublicationKindChirho::PublishChirho,
                slug_chirho: "audit-base-chirho".to_string(),
                outcome_chirho: PublicationOutcomeChirho::AppliedChirho,
                refusal_code_chirho: None,
                params_chirho: Some(HashChirho("d4".repeat(32))),
                params_record_seq_chirho: Some(0),
            },
        )
        .unwrap();
    }
    assert_eq!(
        live_identity_for_slug_for_viewer_chirho(
            &world_chirho.tenant_chirho,
            "audit-base-chirho",
            &viewer_chirho,
            TENANT_LABEL_CHIRHO,
        )
        .unwrap(),
        own_digest_chirho.0,
        "later foreign records must not replace the viewer's own approval base"
    );
    assert_eq!(
        live_identity_for_slug_for_viewer_chirho(
            &world_chirho.tenant_chirho,
            "audit-base-chirho",
            &viewer_chirho,
            "absent-tenant-chirho",
        )
        .unwrap(),
        DARK_PUBLICATION_BASE_CHIRHO,
    );
    std::fs::remove_dir_all(&world_chirho.platform_chirho).unwrap();
}

#[test]
fn audit_replay_precedes_new_foreign_occupancy_chirho() {
    let world_chirho = world_chirho("audit-replay-occupancy-chirho");
    let request_chirho = publish_request_chirho(
        "publish-chirho",
        "audit-raced-chirho",
        "audit-replay-chirho",
        Some(page_chirho("Independent replay witness chirho")),
        None,
        None,
    );
    let first_chirho = intend_chirho(&world_chirho, &request_chirho).unwrap();
    assert_admitted_chirho(&first_chirho, "before another owner deploys");
    let units_chirho = charged_publication_units_chirho(&world_chirho);
    deploy_foreign_platform_app_chirho(&world_chirho.platform_chirho, "audit-raced-chirho");
    assert_eq!(
        intend_chirho(&world_chirho, &request_chirho).unwrap(),
        first_chirho
    );
    assert_eq!(
        charged_publication_units_chirho(&world_chirho),
        units_chirho
    );
    let fresh_chirho = publish_request_chirho(
        "publish-chirho",
        "audit-raced-chirho",
        "audit-fresh-chirho",
        Some(page_chirho("Independent replay witness chirho")),
        None,
        None,
    );
    assert_eq!(
        intend_refused_chirho(&world_chirho, &fresh_chirho).refusal_code_chirho,
        "slug-taken-chirho"
    );
    assert_eq!(
        charged_publication_units_chirho(&world_chirho),
        units_chirho
    );
    std::fs::remove_dir_all(&world_chirho.platform_chirho).unwrap();
}

#[test]
fn audit_applier_refuses_a_slug_taken_after_admission_chirho() {
    let world_chirho = world_chirho("audit-applier-race-chirho");
    register_platform_template_chirho(&world_chirho.platform_chirho);
    let request_chirho = publish_request_chirho(
        "publish-chirho",
        "audit-later-taken-chirho",
        "audit-admit-first-chirho",
        Some(page_chirho(
            "Approved before the competing deployment chirho",
        )),
        None,
        None,
    );
    let admitted_chirho = intend_chirho(&world_chirho, &request_chirho).unwrap();
    assert_admitted_chirho(&admitted_chirho, "the slug is still free at admission");
    let foreign_owner_chirho = deploy_foreign_platform_app_chirho(
        &world_chirho.platform_chirho,
        "audit-later-taken-chirho",
    );
    let report_chirho =
        apply_publication_intents_chirho(&world_chirho.platform_chirho, TENANT_LABEL_CHIRHO)
            .expect(
                "the final applier gate must record slug-taken, not fail later in app mutation",
            );
    assert_eq!(report_chirho.applied_chirho, 0);
    assert_eq!(report_chirho.refused_chirho, 1);
    assert_eq!(
        report_chirho.refusals_chirho.get("slug-taken-chirho"),
        Some(&1)
    );
    assert_eq!(
        crate::app_chirho::verified_app_owner_chirho(
            &world_chirho.platform_chirho,
            "audit-later-taken-chirho",
        )
        .unwrap(),
        Some(foreign_owner_chirho),
    );
    std::fs::remove_dir_all(&world_chirho.platform_chirho).unwrap();
}
