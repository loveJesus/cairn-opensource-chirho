// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish but have everlasting life. - John 3:16 (KJV)

use super::super::*;
use std::collections::BTreeMap;

const CORE_REFS_CHIRHO: &str = "crates/cairn-core-chirho/src/refs_chirho.rs";
const WRITER_HEAD_CRATE_CHIRHO: &str = "crates/support-chirho/cairn-writer-head-chirho";
const WRITER_HEAD_TRANSITION_CHIRHO: &str =
    "crates/support-chirho/cairn-writer-head-chirho/src/head_transition_chirho.rs";
const WRITER_HEAD_AUTHORITY_CHIRHO: &str =
    "crates/support-chirho/cairn-writer-head-chirho/src/head_transition_authority_chirho.rs";
const ONBOARDING_ADOPTER_CHIRHO: &str = "src/edge_flows_chirho/onboarding_chirho.rs";
const PRICEBOOK_ADOPTER_CHIRHO: &str = "src/app_runtime_chirho/effect_pricing_chirho.rs";
/// SPLIT by CF6-D2 brick (a2-3) shape 2, and the split follows the READ/WRITE line rather than
/// cutting across it — which is why it needs two constants and not a repoint.
///
/// Measured per token: the two RECEIPT-VERIFICATION calls
/// (`bind_caller_verified_head_transition_chirho`, `verified_head_transition_receipt_chirho`) went
/// with the current-policy READ into the retained module, because a read that outlives the spine has
/// to carry its own applied-receipt check. The two COMPLETION-PROTOCOL calls
/// (`complete_head_transition_unlocked_chirho`, `pending_head_transition_index_unlocked_chirho`)
/// stayed with the WRITER and die with the spine.
///
/// A single repoint moved all four and turned one red into a DIFFERENT red — the tell that one name
/// was serving two purposes, the same shape as the dual-purpose read entry point this brick split.
///
/// THE SPLIT'S PREDICTION FIRED AS WRITTEN at CF6 wave-1 (2026-07-26). `BILLING_ADOPTER_CHIRHO`
/// (`economic_flows_chirho/billing_chirho.rs`) held the two COMPLETION-PROTOCOL calls and died with
/// the spine exactly as this note said it would; only the retained read-side half below survives.
/// The const and its two inventory rows are gone. Kept as a worked example: the split was made
/// BEFORE the deletion, on a read/write argument, and the deletion then confirmed it — which is what
/// distinguishes a prediction from a rationalisation.
///
/// This constant is the retained half, holding the read-side receipt verification.
const BILLING_EVIDENCE_ADOPTER_CHIRHO: &str =
    "src/legacy_evidence_chirho/legacy_billing_evidence_chirho.rs";
const AGENT_AUTHORITY_ADOPTER_CHIRHO: &str =
    "src/governance_flows_chirho/agent_authority_chirho/mod.rs";
const APP_ROOT_ADOPTER_CHIRHO: &str =
    "src/app_runtime_chirho/app_chirho/head_protocol_chirho/app_head_transition_chirho.rs";
const APP_DEPLOY_EVIDENCE_ADOPTER_CHIRHO: &str =
    "src/app_runtime_chirho/app_chirho/app_deploy_evidence_chirho.rs";
/// S3's price-book elected door. Third adopter of the prepared-fence positive-head family, after
/// the writer-head origin and S1's app-deploy evidence module.
const PRICE_BOOK_EVIDENCE_ADOPTER_CHIRHO: &str =
    "src/app_runtime_chirho/effect_pricing_chirho/price_book_evidence_chirho.rs";
const APP_ROUTE_ADOPTER_CHIRHO: &str = "crates/runtime-chirho/cairn-app-control-chirho/src/lib.rs";
const APP_ROUTE_DEPLOY_EVIDENCE_ADOPTER_CHIRHO: &str =
    "crates/runtime-chirho/cairn-app-control-chirho/src/elected_app_route_deploy_chirho.rs";
const RESOURCE_POLICY_ADOPTER_CHIRHO: &str =
    "src/app_metering_chirho/resource_chirho/policy_head_transition_chirho.rs";
const RESOURCE_POLICY_SET_PATH_CHIRHO: &str = "src/app_metering_chirho/resource_chirho.rs";
const ONBOARDING_ELECTED_ADOPTER_CHIRHO: &str =
    "src/edge_flows_chirho/onboarding_chirho/elected_chirho.rs";
const AGENT_AUTHORITY_ELECTED_ADOPTER_CHIRHO: &str =
    "src/governance_flows_chirho/agent_authority_chirho/elected_chirho.rs";

#[test]
fn positive_head_transition_core_primitive_has_one_reviewed_caller_chirho() {
    let mut counts_chirho = BTreeMap::new();
    let mut sites_chirho = Vec::new();
    for (file_chirho, line_chirho, text_chirho) in
        production_source_lines_matching_chirho("commit_head_with_transition_receipt_chirho(")
    {
        *counts_chirho.entry(file_chirho.clone()).or_insert(0usize) += 1;
        sites_chirho.push(format!("{file_chirho}:{line_chirho}: {text_chirho}"));
    }
    assert_eq!(
        counts_chirho,
        [
            (CORE_REFS_CHIRHO.to_string(), 1usize),
            (WRITER_HEAD_TRANSITION_CHIRHO.to_string(), 1usize),
        ]
        .into_iter()
        .collect(),
        "the mechanism-only core transition primitive must have exactly one reviewed caller in writer-head: {sites_chirho:?}"
    );
}

#[test]
fn positive_head_transition_adopters_stay_in_the_reviewed_family_inventory_chirho() {
    let reviewed_surface_chirho = [
        (
            "bind_caller_verified_head_transition_chirho(",
            [
                (AGENT_AUTHORITY_ADOPTER_CHIRHO, 1usize),
                (APP_ROOT_ADOPTER_CHIRHO, 1usize),
                (APP_ROUTE_ADOPTER_CHIRHO, 1usize),
                (BILLING_EVIDENCE_ADOPTER_CHIRHO, 1usize),
                (ONBOARDING_ADOPTER_CHIRHO, 1usize),
                (WRITER_HEAD_TRANSITION_CHIRHO, 1usize),
                (PRICEBOOK_ADOPTER_CHIRHO, 1usize),
                (RESOURCE_POLICY_ADOPTER_CHIRHO, 1usize),
            ]
            .into_iter()
            .collect::<BTreeMap<_, _>>(),
        ),
        (
            "complete_head_transition_unlocked_chirho(",
            [
                (AGENT_AUTHORITY_ADOPTER_CHIRHO, 2usize),
                (APP_ROOT_ADOPTER_CHIRHO, 2usize),
                (APP_ROUTE_ADOPTER_CHIRHO, 2usize),
                (ONBOARDING_ADOPTER_CHIRHO, 2usize),
                (WRITER_HEAD_AUTHORITY_CHIRHO, 1usize),
                (WRITER_HEAD_TRANSITION_CHIRHO, 2usize),
                (PRICEBOOK_ADOPTER_CHIRHO, 2usize),
                (RESOURCE_POLICY_ADOPTER_CHIRHO, 1usize),
                (RESOURCE_POLICY_SET_PATH_CHIRHO, 1usize),
            ]
            .into_iter()
            .collect::<BTreeMap<_, _>>(),
        ),
        (
            "bind_caller_verified_head_transition_from_prepared_fence_chirho(",
            [
                // C3/G5: both elected control doors prepare signed records without minting a fence.
                (ONBOARDING_ELECTED_ADOPTER_CHIRHO, 1usize),
                (AGENT_AUTHORITY_ELECTED_ADOPTER_CHIRHO, 1usize),
                (APP_DEPLOY_EVIDENCE_ADOPTER_CHIRHO, 1usize),
                (APP_ROUTE_DEPLOY_EVIDENCE_ADOPTER_CHIRHO, 1usize),
                (PRICE_BOOK_EVIDENCE_ADOPTER_CHIRHO, 1usize),
                (WRITER_HEAD_TRANSITION_CHIRHO, 1usize),
            ]
            .into_iter()
            .collect::<BTreeMap<_, _>>(),
        ),
        (
            "derive_head_transition_id_from_prepared_fence_chirho(",
            [
                (ONBOARDING_ELECTED_ADOPTER_CHIRHO, 1usize),
                (AGENT_AUTHORITY_ELECTED_ADOPTER_CHIRHO, 1usize),
                (APP_DEPLOY_EVIDENCE_ADOPTER_CHIRHO, 1usize),
                (APP_ROUTE_DEPLOY_EVIDENCE_ADOPTER_CHIRHO, 1usize),
                (PRICE_BOOK_EVIDENCE_ADOPTER_CHIRHO, 1usize),
                (WRITER_HEAD_TRANSITION_CHIRHO, 1usize),
            ]
            .into_iter()
            .collect::<BTreeMap<_, _>>(),
        ),
        (
            "preflight_head_transition_commit_chirho(",
            [
                (WRITER_HEAD_AUTHORITY_CHIRHO, 1usize),
                (WRITER_HEAD_TRANSITION_CHIRHO, 2usize),
            ]
            .into_iter()
            .collect::<BTreeMap<_, _>>(),
        ),
        (
            "recover_head_transition_chirho(",
            [(WRITER_HEAD_TRANSITION_CHIRHO, 1usize)]
                .into_iter()
                .collect::<BTreeMap<_, _>>(),
        ),
        (
            "pending_head_transition_index_unlocked_chirho(",
            [
                // Recovery classification repairs a torn tail only inside elected COMMIT.
                (ONBOARDING_ELECTED_ADOPTER_CHIRHO, 1usize),
                (AGENT_AUTHORITY_ELECTED_ADOPTER_CHIRHO, 1usize),
                (AGENT_AUTHORITY_ADOPTER_CHIRHO, 1usize),
                (APP_ROOT_ADOPTER_CHIRHO, 1usize),
                (APP_ROUTE_ADOPTER_CHIRHO, 1usize),
                (ONBOARDING_ADOPTER_CHIRHO, 1usize),
                (WRITER_HEAD_TRANSITION_CHIRHO, 1usize),
                (PRICEBOOK_ADOPTER_CHIRHO, 1usize),
                (RESOURCE_POLICY_ADOPTER_CHIRHO, 1usize),
            ]
            .into_iter()
            .collect::<BTreeMap<_, _>>(),
        ),
        (
            "verified_head_transition_receipt_chirho(",
            [
                (ONBOARDING_ELECTED_ADOPTER_CHIRHO, 1usize),
                (AGENT_AUTHORITY_ELECTED_ADOPTER_CHIRHO, 1usize),
                (AGENT_AUTHORITY_ADOPTER_CHIRHO, 1usize),
                // S3: the elected PREPARE refuses a pending unreceipted transition rather than
                // repairing it, so it verifies receipts. See the two-era pricebook guard.
                (PRICE_BOOK_EVIDENCE_ADOPTER_CHIRHO, 1usize),
                (APP_DEPLOY_EVIDENCE_ADOPTER_CHIRHO, 1usize),
                (APP_ROUTE_DEPLOY_EVIDENCE_ADOPTER_CHIRHO, 1usize),
                (APP_ROOT_ADOPTER_CHIRHO, 1usize),
                (APP_ROUTE_ADOPTER_CHIRHO, 1usize),
                (BILLING_EVIDENCE_ADOPTER_CHIRHO, 1usize),
                (ONBOARDING_ADOPTER_CHIRHO, 1usize),
                (PRICEBOOK_ADOPTER_CHIRHO, 1usize),
                (WRITER_HEAD_TRANSITION_CHIRHO, 1usize),
                (RESOURCE_POLICY_ADOPTER_CHIRHO, 1usize),
            ]
            .into_iter()
            .collect::<BTreeMap<_, _>>(),
        ),
    ];
    for (marker_chirho, expected_chirho) in reviewed_surface_chirho {
        let mut actual_chirho = BTreeMap::new();
        for (file_chirho, _line_chirho, _text_chirho) in
            production_source_lines_matching_chirho(marker_chirho)
        {
            *actual_chirho.entry(file_chirho).or_insert(0usize) += 1;
        }
        assert_eq!(
            actual_chirho,
            expected_chirho
                .into_iter()
                .map(|(file_chirho, count_chirho)| (file_chirho.to_string(), count_chirho))
                .collect(),
            "positive-head transition adoption changed outside the reviewed family inventory: {marker_chirho}"
        );
    }
}

#[test]
fn positive_head_transition_dependency_direction_stays_downward_chirho() {
    let cargo_chirho = std::fs::read_to_string(
        workspace_root_chirho().join(format!("{WRITER_HEAD_CRATE_CHIRHO}/Cargo.toml")),
    )
    .unwrap();
    for required_chirho in [
        "cairn-core-chirho",
        "cairn-seqlog-chirho",
        "cairn-signer-chirho",
        "cairn-tenant-chirho",
    ] {
        assert!(
            cargo_chirho.contains(required_chirho),
            "writer-head transition protocol requires downward dependency {required_chirho}"
        );
    }
    for forbidden_chirho in [
        "cairn-chirho =",
        "cairn-cli-chirho",
        "cairn-serve-runtime-chirho",
        "axum",
        "reqwest",
        "stripe",
    ] {
        assert!(
            !cargo_chirho.contains(forbidden_chirho),
            "writer-head transition protocol must not gain upward/network/product dependency {forbidden_chirho}"
        );
    }
}

#[test]
fn positive_head_transition_keeps_verification_before_head_mutation_chirho() {
    let text_chirho =
        std::fs::read_to_string(workspace_root_chirho().join(WRITER_HEAD_TRANSITION_CHIRHO))
            .unwrap();
    let production_chirho = production_text_chirho(&text_chirho);
    for required_chirho in [
        "preflight_head_transition_commit_chirho(",
        "verify_writer_fence_for_root_chirho(",
        "verified_receipt_for_transition_chirho(",
        "sign_message_with_existing_key_chirho(",
        "verify_with_pubkey_chirho(",
        "recover_jsonl_len_unlocked_chirho(",
        "commit_head_with_transition_receipt_chirho(",
    ] {
        assert!(
            production_chirho.contains(required_chirho),
            "head transition trust path must retain {required_chirho}"
        );
    }
    let complete_start_chirho = production_chirho
        .find("pub fn complete_head_transition_unlocked_chirho(")
        .unwrap();
    let complete_chirho = &production_chirho[complete_start_chirho..];
    let preflight_chirho = complete_chirho
        .find("preflight_head_transition_commit_chirho(")
        .unwrap();
    let receipt_chirho = complete_chirho
        .find("verified_receipt_for_transition_chirho(")
        .unwrap();
    let core_chirho = complete_chirho
        .find("commit_head_with_transition_receipt_chirho(")
        .unwrap();
    assert!(
        preflight_chirho < receipt_chirho && receipt_chirho < core_chirho,
        "prepared root/group/epoch/current-fence preflight and signed applied-receipt checks must precede the core ref/reflog mutation"
    );
    let preflight_start_chirho = production_chirho
        .find("pub fn preflight_head_transition_commit_chirho(")
        .unwrap();
    let preflight_end_chirho = production_chirho[preflight_start_chirho..]
        .find("pub fn recover_head_transition_chirho(")
        .map(|offset_chirho| preflight_start_chirho + offset_chirho)
        .unwrap();
    let preflight_body_chirho = &production_chirho[preflight_start_chirho..preflight_end_chirho];
    assert!(
        preflight_body_chirho.contains("root_identity_matches_chirho(")
            && preflight_body_chirho.contains("HeadTransitionWrongGroupChirho")
            && preflight_body_chirho.contains("HeadTransitionPreparedFenceEpochRegressionChirho")
            && preflight_body_chirho.contains("verify_writer_fence_for_root_chirho("),
        "the extracted preflight must retain root, group, lower-bound epoch, and current-fence verification"
    );
}

#[test]
fn applied_receipt_witness_stays_narrow_and_read_only_chirho() {
    let text_chirho =
        std::fs::read_to_string(workspace_root_chirho().join(WRITER_HEAD_TRANSITION_CHIRHO))
            .unwrap();
    let production_chirho = production_text_chirho(&text_chirho);
    let start_chirho = production_chirho
        .find("pub fn verified_head_transition_receipt_chirho(")
        .unwrap();
    let end_chirho = production_chirho[start_chirho..]
        .find("pub fn pending_head_transition_index_unlocked_chirho(")
        .map(|offset_chirho| start_chirho + offset_chirho)
        .unwrap();
    let witness_chirho = &production_chirho[start_chirho..end_chirho];
    assert!(witness_chirho.contains("verified_receipt_for_transition_chirho("));
    for forbidden_chirho in [
        "recover_reflog_tail_chirho(",
        "signed_receipt_chirho(",
        "commit_head_with_transition_receipt_chirho(",
        "sign_message",
        "std::fs",
    ] {
        assert!(
            !witness_chirho.contains(forbidden_chirho),
            "Applied-receipt witness must remain read-only and must not recover or sign via {forbidden_chirho}"
        );
    }
}

#[test]
fn positive_head_transition_surface_stays_read_only_except_reviewed_ref_reflog_commit_chirho() {
    let text_chirho =
        std::fs::read_to_string(workspace_root_chirho().join(WRITER_HEAD_TRANSITION_CHIRHO))
            .unwrap();
    let production_chirho = production_text_chirho(&text_chirho);
    for forbidden_chirho in [
        "sign_message_chirho(",
        "load_or_create_signing_key_chirho(",
        "std::fs::write(",
        "File::create(",
        "OpenOptions",
        "refs_chirho::set_branch_chirho(",
        "refs_chirho::rollback_chirho(",
        "refs_chirho::save_refs_chirho(",
        "append_gate1_authority_record_chirho(",
        "ledger_chirho::",
        "paid_chirho::",
        "provider_chirho::",
        "axum::",
        "Sse",
        "WebSocket",
    ] {
        assert!(
            !production_chirho.contains(forbidden_chirho),
            "head transition protocol contains forbidden authority/product/write surface {forbidden_chirho}"
        );
    }
    assert!(
        !production_chirho.contains("root_chirho.join("),
        "Brick A must extend the tracked reflog and must not create a second persisted log"
    );
}

#[test]
fn core_transition_primitive_stays_mechanism_only_chirho() {
    let text_chirho =
        std::fs::read_to_string(workspace_root_chirho().join(CORE_REFS_CHIRHO)).unwrap();
    let production_chirho = production_text_chirho(&text_chirho);
    assert!(
        production_chirho.contains("This is a mechanism-only primitive."),
        "core transition primitive must state its non-authority contract"
    );
    for forbidden_chirho in [
        "cairn_signer_chirho",
        "verify_with_pubkey_chirho(",
        "sign_message_with_existing_key_chirho(",
        "HEAD_TRANSITION_RECEIPT_SCHEMA_CHIRHO",
    ] {
        assert!(
            !production_chirho.contains(forbidden_chirho),
            "core refs must not promote or verify transition receipt authority via {forbidden_chirho}"
        );
    }
}

#[test]
fn transition_receipt_fields_are_opaque_non_pii_metadata_chirho() {
    let text_chirho =
        std::fs::read_to_string(workspace_root_chirho().join(CORE_REFS_CHIRHO)).unwrap();
    let production_chirho = production_text_chirho(&text_chirho);
    // The required receipt-field-set inventory was demoted to the advisory structure report; the
    // no-PII / no-path-bearing-field engine claim stays RED.
    for forbidden_chirho in [
        "family_line_chirho:",
        "owner_principal_chirho:",
        "private_value_chirho:",
        "root_path_chirho:",
    ] {
        assert!(
            !production_chirho.contains(forbidden_chirho),
            "transition receipt must not add PII/path-bearing field {forbidden_chirho}"
        );
    }
}
