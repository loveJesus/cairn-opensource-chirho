// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Security regressions for root-signed Subscribe cursor mint and resume validation.

use super::*;
use crate::tests_chirho::{
    promote_manifest_chirho, seed_fixture_chirho, snapshot_tree_chirho,
    subscription_manifest_chirho, tmp_root_chirho, verified_witness_chirho, APP_CHIRHO,
    ROOT_VIEW_CHIRHO, ROUTE_CHIRHO, ROUTE_VIEW_CHIRHO,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cairn_chirho::{app_chirho, refs_chirho};
use cairn_gate1_authority_log_chirho::authority_log_chirho::{
    append_gate1_authority_record_chirho, Gate1AuthorityAppendInputChirho,
};
use cairn_model_gate1_chirho::{
    unsigned_gate1_authority_record_message_chirho, GATE1_AUTHORITY_RECORD_DIGEST_PREFIX_CHIRHO,
    GATE1_LEDGER_FAMILY_CHIRHO,
};
use cairn_subscribe_chirho::SubscriptionIdIssuerChirho;
use cairn_writer_head_chirho::writer_head_chirho::issue_writer_fence_for_root_chirho;

const ISSUED_AT_MS_CHIRHO: u64 = 50_000;
const VALID_NOW_MS_CHIRHO: u64 = 50_001;
static APP_ROOT_TARGET_CHIRHO: SubscriptionViewTargetChirho =
    SubscriptionViewTargetChirho::AppRootChirho;

#[derive(Default)]
struct CountingCursorSourceChirho {
    reads_chirho: usize,
    replacement_records_chirho: Option<Vec<Gate1AuthorityLogRecordChirho>>,
}

impl Gate1CursorSourceChirho for CountingCursorSourceChirho {
    fn verified_records_chirho(
        &mut self,
        root_chirho: &Path,
    ) -> Result<Vec<Gate1AuthorityLogRecordChirho>> {
        self.reads_chirho += 1;
        if let Some(records_chirho) = &self.replacement_records_chirho {
            return Ok(records_chirho.clone());
        }
        RootGate1CursorSourceChirho.verified_records_chirho(root_chirho)
    }
}

fn append_authority_record_chirho(root_chirho: &Path) -> Gate1AuthorityLogRecordChirho {
    let token_chirho = issue_writer_fence_for_root_chirho(root_chirho).unwrap();
    append_gate1_authority_record_chirho(
        root_chirho,
        &token_chirho,
        Gate1AuthorityAppendInputChirho {
            family_chirho: GATE1_LEDGER_FAMILY_CHIRHO,
            family_seq_chirho: 0,
            family_line_chirho: "{\"seq_chirho\":0,\"amount_chirho\":7}",
            at_ms_chirho: 1_000,
        },
    )
    .unwrap()
    .record_chirho
}

fn mint_token_chirho(
    root_chirho: &Path,
    owner_chirho: &str,
    subscription_id_chirho: SubscriptionIdChirho,
    next_source_seq_chirho: u64,
) -> OpaqueSubscriptionCursorTokenChirho {
    let witness_chirho =
        verified_witness_chirho(current_subscription_control_plane_witness_chirho(
            root_chirho,
            owner_chirho,
            APP_CHIRHO,
            &SubscriptionViewTargetChirho::AppRootChirho,
            ROOT_VIEW_CHIRHO,
        ));
    match mint_gate1_subscription_cursor_chirho(
        root_chirho,
        &witness_chirho,
        subscription_id_chirho,
        Gate1AuthorityCursorChirho {
            next_authority_seq_chirho: next_source_seq_chirho,
        },
        ISSUED_AT_MS_CHIRHO,
    ) {
        SubscriptionCursorMintOutcomeChirho::MintedChirho(token_chirho) => token_chirho,
        SubscriptionCursorMintOutcomeChirho::ResnapshotRequiredChirho => {
            panic!("expected signed cursor token")
        }
    }
}

fn assert_resume_required_chirho(outcome_chirho: SubscriptionCursorResumeOutcomeChirho) {
    assert!(matches!(
        outcome_chirho,
        SubscriptionCursorResumeOutcomeChirho::ResnapshotRequiredChirho
    ));
}

fn resume_context_chirho<'a>(
    owner_chirho: &'a str,
    view_chirho: &'a str,
    now_ms_chirho: u64,
) -> SubscriptionResumeContextChirho<'a> {
    SubscriptionResumeContextChirho {
        authenticated_principal_chirho: owner_chirho,
        app_chirho: APP_CHIRHO,
        target_chirho: &APP_ROOT_TARGET_CHIRHO,
        view_chirho,
        now_ms_chirho,
    }
}

fn decode_envelope_chirho(
    token_chirho: &OpaqueSubscriptionCursorTokenChirho,
) -> SignedSubscriptionCursorEnvelopeChirho {
    decode_cursor_chirho(token_chirho).unwrap()
}

fn resign_envelope_chirho(
    root_chirho: &Path,
    mut envelope_chirho: SignedSubscriptionCursorEnvelopeChirho,
) -> OpaqueSubscriptionCursorTokenChirho {
    envelope_chirho.sig_chirho.clear();
    let message_chirho = unsigned_cursor_message_chirho(&envelope_chirho).unwrap();
    envelope_chirho.sig_chirho =
        signer_chirho::sign_message_with_existing_key_chirho(root_chirho, &message_chirho).unwrap();
    encode_cursor_chirho(&envelope_chirho).unwrap()
}

#[test]
fn valid_cursor_mint_and_resume_are_byte_unchanged_and_read_once_chirho() {
    let fixture_chirho = seed_fixture_chirho();
    append_authority_record_chirho(&fixture_chirho.root_chirho);
    let witness_chirho =
        verified_witness_chirho(current_subscription_control_plane_witness_chirho(
            &fixture_chirho.root_chirho,
            &fixture_chirho.owner_chirho,
            APP_CHIRHO,
            &SubscriptionViewTargetChirho::AppRootChirho,
            ROOT_VIEW_CHIRHO,
        ));
    let mut issuer_chirho = SubscriptionIdIssuerChirho::default();
    let subscription_id_chirho = issuer_chirho.mint_chirho().unwrap();
    let before_chirho = snapshot_tree_chirho(&fixture_chirho.root_chirho);
    let mut mint_source_chirho = CountingCursorSourceChirho::default();
    let token_chirho = try_mint_gate1_subscription_cursor_chirho(
        &fixture_chirho.root_chirho,
        &witness_chirho,
        subscription_id_chirho,
        Gate1AuthorityCursorChirho {
            next_authority_seq_chirho: 1,
        },
        ISSUED_AT_MS_CHIRHO,
        &mut mint_source_chirho,
    )
    .unwrap();
    assert_eq!(mint_source_chirho.reads_chirho, 1);

    let mut resume_source_chirho = CountingCursorSourceChirho::default();
    let validated_chirho = try_resume_gate1_subscription_cursor_chirho(
        &fixture_chirho.root_chirho,
        &token_chirho,
        &resume_context_chirho(
            &fixture_chirho.owner_chirho,
            ROOT_VIEW_CHIRHO,
            VALID_NOW_MS_CHIRHO,
        ),
        &mut resume_source_chirho,
    )
    .unwrap();
    assert_eq!(resume_source_chirho.reads_chirho, 1);
    assert!(validated_chirho.subscription_id_matches_chirho(subscription_id_chirho));
    assert_eq!(
        validated_chirho.cursor_chirho().next_authority_seq_chirho,
        1
    );
    assert_eq!(
        snapshot_tree_chirho(&fixture_chirho.root_chirho),
        before_chirho
    );

    let decoded_chirho = URL_SAFE_NO_PAD
        .decode(token_chirho.as_str_chirho())
        .unwrap();
    let decoded_text_chirho = String::from_utf8(decoded_chirho).unwrap();
    for forbidden_chirho in [
        APP_CHIRHO,
        ROOT_VIEW_CHIRHO,
        fixture_chirho.owner_chirho.as_str(),
        fixture_chirho.root_chirho.to_str().unwrap(),
        "family_line_chirho",
        "amount_chirho",
    ] {
        assert!(!decoded_text_chirho.contains(forbidden_chirho));
    }
    let _ = std::fs::remove_dir_all(fixture_chirho.root_chirho);
}

#[test]
fn stream_zero_mints_and_beyond_tail_fails_generically_chirho() {
    let fixture_chirho = seed_fixture_chirho();
    let mut issuer_chirho = SubscriptionIdIssuerChirho::default();
    let subscription_id_chirho = issuer_chirho.mint_chirho().unwrap();
    let zero_token_chirho = mint_token_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.owner_chirho,
        subscription_id_chirho,
        0,
    );
    let zero_envelope_chirho = decode_envelope_chirho(&zero_token_chirho);
    assert!(zero_envelope_chirho.previous_record_digest_chirho.is_none());

    let witness_chirho =
        verified_witness_chirho(current_subscription_control_plane_witness_chirho(
            &fixture_chirho.root_chirho,
            &fixture_chirho.owner_chirho,
            APP_CHIRHO,
            &SubscriptionViewTargetChirho::AppRootChirho,
            ROOT_VIEW_CHIRHO,
        ));
    assert!(matches!(
        mint_gate1_subscription_cursor_chirho(
            &fixture_chirho.root_chirho,
            &witness_chirho,
            subscription_id_chirho,
            Gate1AuthorityCursorChirho {
                next_authority_seq_chirho: 1,
            },
            ISSUED_AT_MS_CHIRHO,
        ),
        SubscriptionCursorMintOutcomeChirho::ResnapshotRequiredChirho
    ));
    let _ = std::fs::remove_dir_all(fixture_chirho.root_chirho);
}

#[test]
fn self_certifying_foreign_key_cursor_fails_before_source_read_chirho() {
    let fixture_chirho = seed_fixture_chirho();
    let foreign_root_chirho = tmp_root_chirho();
    signer_chirho::sign_message_chirho(&foreign_root_chirho, b"foreign cursor key").unwrap();
    let mut issuer_chirho = SubscriptionIdIssuerChirho::default();
    let token_chirho = mint_token_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.owner_chirho,
        issuer_chirho.mint_chirho().unwrap(),
        0,
    );
    let mut envelope_chirho = decode_envelope_chirho(&token_chirho);
    envelope_chirho.key_id_chirho =
        signer_chirho::existing_pubkey_hex_chirho(&foreign_root_chirho).unwrap();
    let forged_chirho = resign_envelope_chirho(&foreign_root_chirho, envelope_chirho);
    let mut source_chirho = CountingCursorSourceChirho::default();
    assert!(try_resume_gate1_subscription_cursor_chirho(
        &fixture_chirho.root_chirho,
        &forged_chirho,
        &resume_context_chirho(
            &fixture_chirho.owner_chirho,
            ROOT_VIEW_CHIRHO,
            VALID_NOW_MS_CHIRHO,
        ),
        &mut source_chirho,
    )
    .is_err());
    assert_eq!(source_chirho.reads_chirho, 0);

    let mut foreign_replay_source_chirho = CountingCursorSourceChirho::default();
    assert!(try_resume_gate1_subscription_cursor_chirho(
        &foreign_root_chirho,
        &token_chirho,
        &resume_context_chirho(
            &fixture_chirho.owner_chirho,
            ROOT_VIEW_CHIRHO,
            VALID_NOW_MS_CHIRHO,
        ),
        &mut foreign_replay_source_chirho,
    )
    .is_err());
    assert_eq!(foreign_replay_source_chirho.reads_chirho, 0);
    let _ = std::fs::remove_dir_all(fixture_chirho.root_chirho);
    let _ = std::fs::remove_dir_all(foreign_root_chirho);
}

#[test]
fn valid_signature_rechecks_current_authorization_and_rollback_chirho() {
    let fixture_chirho = seed_fixture_chirho();
    let mut issuer_chirho = SubscriptionIdIssuerChirho::default();
    let token_chirho = mint_token_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.owner_chirho,
        issuer_chirho.mint_chirho().unwrap(),
        0,
    );
    let mut replacement_manifest_chirho = fixture_chirho.manifest_chirho.clone();
    replacement_manifest_chirho.nodes_chirho[0].name_chirho =
        "cursor-replacement-node-chirho".to_string();
    let replacement_dag_chirho = promote_manifest_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.owner_chirho,
        &replacement_manifest_chirho,
    );
    assert_ne!(replacement_dag_chirho, fixture_chirho.app_dag_chirho);
    assert_resume_required_chirho(resume_gate1_subscription_cursor_chirho(
        &fixture_chirho.root_chirho,
        &token_chirho,
        &fixture_chirho.owner_chirho,
        APP_CHIRHO,
        &SubscriptionViewTargetChirho::AppRootChirho,
        ROOT_VIEW_CHIRHO,
        VALID_NOW_MS_CHIRHO,
    ));

    refs_chirho::set_branch_chirho(
        &fixture_chirho.root_chirho,
        &format!("app/{APP_CHIRHO}"),
        fixture_chirho.app_dag_chirho.clone(),
    )
    .unwrap();
    assert!(matches!(
        resume_gate1_subscription_cursor_chirho(
            &fixture_chirho.root_chirho,
            &token_chirho,
            &fixture_chirho.owner_chirho,
            APP_CHIRHO,
            &SubscriptionViewTargetChirho::AppRootChirho,
            ROOT_VIEW_CHIRHO,
            VALID_NOW_MS_CHIRHO,
        ),
        SubscriptionCursorResumeOutcomeChirho::ValidatedChirho(_)
    ));

    app_chirho::undeploy_app_chirho(
        &fixture_chirho.root_chirho,
        APP_CHIRHO,
        &fixture_chirho.owner_chirho,
    )
    .unwrap();
    assert_resume_required_chirho(resume_gate1_subscription_cursor_chirho(
        &fixture_chirho.root_chirho,
        &token_chirho,
        &fixture_chirho.owner_chirho,
        APP_CHIRHO,
        &SubscriptionViewTargetChirho::AppRootChirho,
        ROOT_VIEW_CHIRHO,
        VALID_NOW_MS_CHIRHO,
    ));
    let _ = std::fs::remove_dir_all(fixture_chirho.root_chirho);
}

#[test]
fn declaration_and_cross_context_changes_fail_before_source_read_chirho() {
    let fixture_chirho = seed_fixture_chirho();
    let mut issuer_chirho = SubscriptionIdIssuerChirho::default();
    let token_chirho = mint_token_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.owner_chirho,
        issuer_chirho.mint_chirho().unwrap(),
        0,
    );
    for (principal_chirho, view_chirho) in [
        ("owner/not-current-chirho", ROOT_VIEW_CHIRHO),
        (fixture_chirho.owner_chirho.as_str(), "wrong-view-chirho"),
    ] {
        let mut source_chirho = CountingCursorSourceChirho::default();
        assert!(try_resume_gate1_subscription_cursor_chirho(
            &fixture_chirho.root_chirho,
            &token_chirho,
            &resume_context_chirho(principal_chirho, view_chirho, VALID_NOW_MS_CHIRHO),
            &mut source_chirho,
        )
        .is_err());
        assert_eq!(source_chirho.reads_chirho, 0);
    }
    let wrong_app_context_chirho = SubscriptionResumeContextChirho {
        authenticated_principal_chirho: &fixture_chirho.owner_chirho,
        app_chirho: "other-app-chirho",
        target_chirho: &APP_ROOT_TARGET_CHIRHO,
        view_chirho: ROOT_VIEW_CHIRHO,
        now_ms_chirho: VALID_NOW_MS_CHIRHO,
    };
    let mut wrong_app_source_chirho = CountingCursorSourceChirho::default();
    assert!(try_resume_gate1_subscription_cursor_chirho(
        &fixture_chirho.root_chirho,
        &token_chirho,
        &wrong_app_context_chirho,
        &mut wrong_app_source_chirho,
    )
    .is_err());
    assert_eq!(wrong_app_source_chirho.reads_chirho, 0);
    let route_target_chirho = SubscriptionViewTargetChirho::RouteChirho {
        route_chirho: ROUTE_CHIRHO.to_string(),
    };
    let wrong_route_context_chirho = SubscriptionResumeContextChirho {
        authenticated_principal_chirho: &fixture_chirho.owner_chirho,
        app_chirho: APP_CHIRHO,
        target_chirho: &route_target_chirho,
        view_chirho: ROUTE_VIEW_CHIRHO,
        now_ms_chirho: VALID_NOW_MS_CHIRHO,
    };
    let mut wrong_route_source_chirho = CountingCursorSourceChirho::default();
    assert!(try_resume_gate1_subscription_cursor_chirho(
        &fixture_chirho.root_chirho,
        &token_chirho,
        &wrong_route_context_chirho,
        &mut wrong_route_source_chirho,
    )
    .is_err());
    assert_eq!(wrong_route_source_chirho.reads_chirho, 0);

    let mut changed_manifest_chirho = subscription_manifest_chirho(&fixture_chirho.owner_chirho);
    changed_manifest_chirho.modules_chirho[0].subscription_views_chirho[0].dependencies_chirho[0]
        .module_input_chirho = "holds-chirho".to_string();
    changed_manifest_chirho.modules_chirho[0].subscription_views_chirho[0]
        .dependencies_chirho[0]
        .group_chirho =
        cairn_chirho::app_source_manifest_chirho::SubscriptionViewDependencyGroupChirho::HoldsChirho;
    let unchanged_dag_chirho = promote_manifest_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.owner_chirho,
        &changed_manifest_chirho,
    );
    assert_eq!(unchanged_dag_chirho, fixture_chirho.app_dag_chirho);
    let mut source_chirho = CountingCursorSourceChirho::default();
    assert!(try_resume_gate1_subscription_cursor_chirho(
        &fixture_chirho.root_chirho,
        &token_chirho,
        &resume_context_chirho(
            &fixture_chirho.owner_chirho,
            ROOT_VIEW_CHIRHO,
            VALID_NOW_MS_CHIRHO,
        ),
        &mut source_chirho,
    )
    .is_err());
    assert_eq!(source_chirho.reads_chirho, 0);
    let _ = std::fs::remove_dir_all(fixture_chirho.root_chirho);
}

#[test]
fn route_removal_invalidates_a_still_root_signed_cursor_chirho() {
    let fixture_chirho = seed_fixture_chirho();
    let route_target_chirho = SubscriptionViewTargetChirho::RouteChirho {
        route_chirho: ROUTE_CHIRHO.to_string(),
    };
    let route_witness_chirho =
        verified_witness_chirho(current_subscription_control_plane_witness_chirho(
            &fixture_chirho.root_chirho,
            &fixture_chirho.owner_chirho,
            APP_CHIRHO,
            &route_target_chirho,
            ROUTE_VIEW_CHIRHO,
        ));
    let mut issuer_chirho = SubscriptionIdIssuerChirho::default();
    let token_chirho = match mint_gate1_subscription_cursor_chirho(
        &fixture_chirho.root_chirho,
        &route_witness_chirho,
        issuer_chirho.mint_chirho().unwrap(),
        Gate1AuthorityCursorChirho::default(),
        ISSUED_AT_MS_CHIRHO,
    ) {
        SubscriptionCursorMintOutcomeChirho::MintedChirho(token_chirho) => token_chirho,
        SubscriptionCursorMintOutcomeChirho::ResnapshotRequiredChirho => {
            panic!("expected route cursor")
        }
    };
    app_chirho::undeploy_app_route_chirho(
        &fixture_chirho.root_chirho,
        APP_CHIRHO,
        ROUTE_CHIRHO,
        &fixture_chirho.owner_chirho,
    )
    .unwrap();
    assert_resume_required_chirho(resume_gate1_subscription_cursor_chirho(
        &fixture_chirho.root_chirho,
        &token_chirho,
        &fixture_chirho.owner_chirho,
        APP_CHIRHO,
        &route_target_chirho,
        ROUTE_VIEW_CHIRHO,
        VALID_NOW_MS_CHIRHO,
    ));
    let _ = std::fs::remove_dir_all(fixture_chirho.root_chirho);
}

#[test]
fn malformed_and_invalid_time_tokens_share_generic_resnapshot_chirho() {
    let fixture_chirho = seed_fixture_chirho();
    let mut issuer_chirho = SubscriptionIdIssuerChirho::default();
    let token_chirho = mint_token_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.owner_chirho,
        issuer_chirho.mint_chirho().unwrap(),
        0,
    );
    let resume_chirho = |token_chirho: &OpaqueSubscriptionCursorTokenChirho, now_ms_chirho| {
        resume_gate1_subscription_cursor_chirho(
            &fixture_chirho.root_chirho,
            token_chirho,
            &fixture_chirho.owner_chirho,
            APP_CHIRHO,
            &SubscriptionViewTargetChirho::AppRootChirho,
            ROOT_VIEW_CHIRHO,
            now_ms_chirho,
        )
    };
    assert_resume_required_chirho(resume_chirho(
        &token_chirho,
        ISSUED_AT_MS_CHIRHO + SUBSCRIPTION_CURSOR_TTL_MS_CHIRHO,
    ));
    assert_resume_required_chirho(resume_chirho(&token_chirho, ISSUED_AT_MS_CHIRHO - 1));

    let mut wrong_ttl_chirho = decode_envelope_chirho(&token_chirho);
    wrong_ttl_chirho.expires_at_ms_chirho += 1;
    let wrong_ttl_chirho = resign_envelope_chirho(&fixture_chirho.root_chirho, wrong_ttl_chirho);
    assert_resume_required_chirho(resume_chirho(&wrong_ttl_chirho, VALID_NOW_MS_CHIRHO));

    let mut bad_hex_chirho = decode_envelope_chirho(&token_chirho);
    bad_hex_chirho.root_identity_digest_chirho.0 = "A".repeat(64);
    let bad_hex_chirho = resign_envelope_chirho(&fixture_chirho.root_chirho, bad_hex_chirho);
    assert_resume_required_chirho(resume_chirho(&bad_hex_chirho, VALID_NOW_MS_CHIRHO));

    let padded_chirho =
        OpaqueSubscriptionCursorTokenChirho(format!("{}=", token_chirho.as_str_chirho()));
    assert_resume_required_chirho(resume_chirho(&padded_chirho, VALID_NOW_MS_CHIRHO));
    let oversized_chirho = OpaqueSubscriptionCursorTokenChirho("a".repeat(4_097));
    assert_resume_required_chirho(resume_chirho(&oversized_chirho, VALID_NOW_MS_CHIRHO));

    let decoded_chirho = URL_SAFE_NO_PAD
        .decode(token_chirho.as_str_chirho())
        .unwrap();
    let mut noncanonical_chirho = decoded_chirho.clone();
    noncanonical_chirho.push(b' ');
    let noncanonical_chirho =
        OpaqueSubscriptionCursorTokenChirho(URL_SAFE_NO_PAD.encode(noncanonical_chirho));
    assert_resume_required_chirho(resume_chirho(&noncanonical_chirho, VALID_NOW_MS_CHIRHO));

    let mut value_chirho: serde_json::Value = serde_json::from_slice(&decoded_chirho).unwrap();
    value_chirho
        .as_object_mut()
        .unwrap()
        .insert("unknown_chirho".to_string(), serde_json::Value::Bool(true));
    let unknown_chirho = OpaqueSubscriptionCursorTokenChirho(
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value_chirho).unwrap()),
    );
    assert_resume_required_chirho(resume_chirho(&unknown_chirho, VALID_NOW_MS_CHIRHO));

    let mut tampered_bytes_chirho = token_chirho.as_str_chirho().as_bytes().to_vec();
    tampered_bytes_chirho[0] = if tampered_bytes_chirho[0] == b'A' {
        b'B'
    } else {
        b'A'
    };
    let tampered_chirho =
        OpaqueSubscriptionCursorTokenChirho(String::from_utf8(tampered_bytes_chirho).unwrap());
    assert_resume_required_chirho(resume_chirho(&tampered_chirho, VALID_NOW_MS_CHIRHO));
    let _ = std::fs::remove_dir_all(fixture_chirho.root_chirho);
}

#[test]
fn tail_bounds_previous_digest_and_same_count_substitution_fail_closed_chirho() {
    let fixture_chirho = seed_fixture_chirho();
    let original_record_chirho = append_authority_record_chirho(&fixture_chirho.root_chirho);
    let mut issuer_chirho = SubscriptionIdIssuerChirho::default();
    let token_chirho = mint_token_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.owner_chirho,
        issuer_chirho.mint_chirho().unwrap(),
        1,
    );

    let mut wrong_previous_chirho = decode_envelope_chirho(&token_chirho);
    wrong_previous_chirho.previous_record_digest_chirho = Some(format!(
        "{GATE1_AUTHORITY_RECORD_DIGEST_PREFIX_CHIRHO}{}",
        "0".repeat(64)
    ));
    let wrong_previous_chirho =
        resign_envelope_chirho(&fixture_chirho.root_chirho, wrong_previous_chirho);
    assert_resume_required_chirho(resume_gate1_subscription_cursor_chirho(
        &fixture_chirho.root_chirho,
        &wrong_previous_chirho,
        &fixture_chirho.owner_chirho,
        APP_CHIRHO,
        &SubscriptionViewTargetChirho::AppRootChirho,
        ROOT_VIEW_CHIRHO,
        VALID_NOW_MS_CHIRHO,
    ));

    let mut beyond_tail_chirho = decode_envelope_chirho(&token_chirho);
    beyond_tail_chirho.next_source_seq_chirho = 2;
    let beyond_tail_chirho =
        resign_envelope_chirho(&fixture_chirho.root_chirho, beyond_tail_chirho);
    assert_resume_required_chirho(resume_gate1_subscription_cursor_chirho(
        &fixture_chirho.root_chirho,
        &beyond_tail_chirho,
        &fixture_chirho.owner_chirho,
        APP_CHIRHO,
        &SubscriptionViewTargetChirho::AppRootChirho,
        ROOT_VIEW_CHIRHO,
        VALID_NOW_MS_CHIRHO,
    ));

    let mut substituted_record_chirho = original_record_chirho;
    substituted_record_chirho.at_ms_chirho += 1;
    substituted_record_chirho.sig_chirho.clear();
    let substituted_message_chirho =
        unsigned_gate1_authority_record_message_chirho(&substituted_record_chirho).unwrap();
    substituted_record_chirho.sig_chirho = signer_chirho::sign_message_with_existing_key_chirho(
        &fixture_chirho.root_chirho,
        &substituted_message_chirho,
    )
    .unwrap();
    let mut substituted_source_chirho = CountingCursorSourceChirho {
        reads_chirho: 0,
        replacement_records_chirho: Some(vec![substituted_record_chirho]),
    };
    assert!(try_resume_gate1_subscription_cursor_chirho(
        &fixture_chirho.root_chirho,
        &token_chirho,
        &resume_context_chirho(
            &fixture_chirho.owner_chirho,
            ROOT_VIEW_CHIRHO,
            VALID_NOW_MS_CHIRHO,
        ),
        &mut substituted_source_chirho,
    )
    .is_err());
    assert_eq!(substituted_source_chirho.reads_chirho, 1);
    let _ = std::fs::remove_dir_all(fixture_chirho.root_chirho);
}
