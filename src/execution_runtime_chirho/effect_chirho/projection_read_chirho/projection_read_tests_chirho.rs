// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use cairn_ledger_composition_chirho::ProjectionWatermarkChirho;
use cairn_ledger_model_chirho::{ids_chirho::DigestChirho, record_chirho::HlcChirho, LogIdChirho};
use cairn_ledger_read_model_chirho::{
    canonical_account_net_projection_view_chirho,
    parse_canonical_account_net_projection_view_chirho, AccountNetProjectionRowChirho,
    AccountNetProjectionViewChirho, VerifiedProjectionReadCutChirho,
    VerifiedProjectionSourceHeadChirho, ACCOUNT_NET_PROJECTION_VIEW_SCHEMA_V1_CHIRHO,
};

fn evidence_view_chirho() -> PublishedProjectionViewChirho {
    PublishedProjectionViewChirho {
        descriptor_ref_chirho: DigestChirho("descriptor-digest-chirho".to_string()),
        watermark_chirho: ProjectionWatermarkChirho {
            source_family_id_chirho: "credits-family-chirho".to_string(),
            source_seq_chirho: 12,
            source_hlc_chirho: HlcChirho {
                physical_ms_chirho: 1_725_000_000_000,
                logical_chirho: 3,
            },
            signed_prefix_digest_chirho: DigestChirho("prefix-digest-chirho".to_string()),
        },
        state_digest_chirho: DigestChirho("state-digest-chirho".to_string()),
    }
}

fn evidence_cut_chirho() -> VerifiedProjectionReadCutChirho {
    let view_chirho = evidence_view_chirho();
    VerifiedProjectionReadCutChirho {
        descriptor_ref_chirho: view_chirho.descriptor_ref_chirho.clone(),
        view_prefix_chirho: view_chirho.watermark_chirho.clone(),
        current_head_chirho: VerifiedProjectionSourceHeadChirho {
            source_family_id_chirho: view_chirho.watermark_chirho.source_family_id_chirho,
            source_seq_chirho: view_chirho.watermark_chirho.source_seq_chirho,
            source_hlc_chirho: view_chirho.watermark_chirho.source_hlc_chirho,
            signed_prefix_digest_chirho: view_chirho.watermark_chirho.signed_prefix_digest_chirho,
        },
    }
}

fn classified_read_chirho(
    outcome_chirho: ProjectionReadOutcomeChirho,
    view_bytes_chirho: Option<Vec<u8>>,
) -> ComposedProjectionReadChirho {
    ComposedProjectionReadChirho {
        view_bytes_chirho,
        verified_cost_class_chirho: Some(ProjectionCostClassChirho::StandingWriteRateChirho),
        outcome_chirho: FollowerServeOutcomeChirho::ReadChirho(outcome_chirho),
    }
}

fn viewer_bound_response_chirho(
    read_chirho: ComposedProjectionReadChirho,
) -> Result<PublishedProjectionReadResponseChirho> {
    response_from_composed_read_chirho(read_chirho, "user/0123456789abcdef")
}

#[test]
fn degraded_transport_preserves_verdict_and_exact_canonical_view_chirho() {
    let response_chirho = viewer_bound_response_chirho(classified_read_chirho(
        ProjectionReadOutcomeChirho::DegradedChirho {
            view_chirho: evidence_view_chirho(),
            lag_ms_chirho: 2,
            max_lag_ms_chirho: 5,
        },
        Some(br#"{"balance_chirho":7}"#.to_vec()),
    ))
    .unwrap();

    assert_eq!(
        response_chirho.cost_class_chirho,
        Some(PublishedProjectionCostClassChirho::StandingWriteRateChirho)
    );
    assert_eq!(
        response_chirho.viewer_principal_chirho,
        "user/0123456789abcdef"
    );
    assert_eq!(
        response_chirho.view_chirho,
        Some(serde_json::json!({"balance_chirho": 7}))
    );
    assert!(matches!(
        response_chirho.outcome_chirho,
        PublishedProjectionVerdictChirho::DegradedChirho {
            lag_ms_chirho: 2,
            max_lag_ms_chirho: 5,
            ..
        }
    ));
}

#[test]
fn refused_verdicts_never_carry_view_bytes_chirho() {
    let classifier_response_chirho = viewer_bound_response_chirho(classified_read_chirho(
        ProjectionReadOutcomeChirho::RefusedChirho(
            FollowerReadRefusalChirho::StaleBeyondContractChirho {
                lag_ms_chirho: 9,
                max_lag_ms_chirho: 5,
            },
        ),
        None,
    ))
    .unwrap();
    assert!(classifier_response_chirho.view_chirho.is_none());
    assert!(matches!(
        classifier_response_chirho.outcome_chirho,
        PublishedProjectionVerdictChirho::ClassifierRefusedChirho {
            refusal_chirho: PublishedProjectionClassifierRefusalChirho::StaleBeyondContractChirho {
                lag_ms_chirho: 9,
                max_lag_ms_chirho: 5,
            },
        }
    ));

    let effect_cut_response_chirho = viewer_bound_response_chirho(classified_read_chirho(
        ProjectionReadOutcomeChirho::RefusedChirho(
            FollowerReadRefusalChirho::EffectCutBehindChirho,
        ),
        None,
    ))
    .unwrap();
    assert!(effect_cut_response_chirho.view_chirho.is_none());
    assert!(matches!(
        effect_cut_response_chirho.outcome_chirho,
        PublishedProjectionVerdictChirho::ClassifierRefusedChirho {
            refusal_chirho: PublishedProjectionClassifierRefusalChirho::EffectCutBehindChirho,
        }
    ));

    let gate_response_chirho = viewer_bound_response_chirho(ComposedProjectionReadChirho {
        view_bytes_chirho: None,
        verified_cost_class_chirho: None,
        outcome_chirho: FollowerServeOutcomeChirho::GateRefusedChirho(
            ServeGateRefusalChirho::ProjectionRetiredChirho,
        ),
    })
    .unwrap();
    assert!(gate_response_chirho.view_chirho.is_none());
    assert!(gate_response_chirho.cost_class_chirho.is_none());
    assert!(matches!(
        gate_response_chirho.outcome_chirho,
        PublishedProjectionVerdictChirho::GateRefusedChirho {
            refusal_chirho: PublishedProjectionGateRefusalChirho::ProjectionRetiredChirho,
        }
    ));
}

#[test]
fn servable_transport_refuses_noncanonical_or_unpriced_view_chirho() {
    let noncanonical_error_chirho = viewer_bound_response_chirho(classified_read_chirho(
        ProjectionReadOutcomeChirho::fresh_from_verified_cut_chirho(
            &evidence_cut_chirho(),
            evidence_view_chirho(),
            0,
        ),
        Some(br#"{ "balance_chirho": 7 }"#.to_vec()),
    ))
    .unwrap_err();
    assert!(noncanonical_error_chirho
        .to_string()
        .contains("not exact-canonical"));

    let unpriced_error_chirho = viewer_bound_response_chirho(ComposedProjectionReadChirho {
        view_bytes_chirho: Some(br#"{"balance_chirho":7}"#.to_vec()),
        verified_cost_class_chirho: None,
        outcome_chirho: FollowerServeOutcomeChirho::ReadChirho(
            ProjectionReadOutcomeChirho::fresh_from_verified_cut_chirho(
                &evidence_cut_chirho(),
                evidence_view_chirho(),
                0,
            ),
        ),
    })
    .unwrap_err();
    assert!(unpriced_error_chirho
        .to_string()
        .contains("omitted its verified cost class"));
}

#[test]
fn account_net_producer_bytes_pass_the_served_canonical_gate_chirho() {
    let view_chirho = AccountNetProjectionViewChirho {
        schema_chirho: ACCOUNT_NET_PROJECTION_VIEW_SCHEMA_V1_CHIRHO.to_owned(),
        rows_chirho: vec![AccountNetProjectionRowChirho {
            account_chirho: LogIdChirho::new_chirho(
                "user/0123456789abcdef",
                "prepaid-credits-chirho",
            ),
            account_net_chirho: 750,
        }],
    };
    let producer_bytes_chirho = canonical_account_net_projection_view_chirho(&view_chirho).unwrap();
    let served_value_chirho =
        exact_canonical_json_view_chirho(Some(producer_bytes_chirho.clone())).unwrap();
    assert_eq!(
        served_value_chirho["rows_chirho"][0]["account_chirho"]["owner_chirho"],
        "user/0123456789abcdef"
    );
    assert_eq!(
        served_value_chirho["rows_chirho"][0]["account_net_chirho"],
        750
    );
    assert_eq!(
        parse_canonical_account_net_projection_view_chirho(&producer_bytes_chirho).unwrap(),
        view_chirho
    );

    let reordered_chirho = br#"{"schema_chirho":"ledger-account-net-projection-view-v1-chirho","rows_chirho":[{"account_chirho":{"owner_chirho":"user/0123456789abcdef","kind_id_chirho":"prepaid-credits-chirho"},"account_net_chirho":750}]}"#;
    let whitespace_chirho = br#"{ "rows_chirho":[{"account_chirho":{"kind_id_chirho":"prepaid-credits-chirho","owner_chirho":"user/0123456789abcdef"},"account_net_chirho":750}],"schema_chirho":"ledger-account-net-projection-view-v1-chirho"}"#;
    let duplicate_chirho = br#"{"rows_chirho":[{"account_chirho":{"kind_id_chirho":"prepaid-credits-chirho","owner_chirho":"user/0123456789abcdef"},"account_net_chirho":750}],"schema_chirho":"ledger-account-net-projection-view-v1-chirho","schema_chirho":"ledger-account-net-projection-view-v1-chirho"}"#;
    for tampered_chirho in [
        reordered_chirho.as_slice(),
        whitespace_chirho.as_slice(),
        duplicate_chirho.as_slice(),
    ] {
        assert!(exact_canonical_json_view_chirho(Some(tampered_chirho.to_vec())).is_err());
    }
}

#[test]
fn refused_transport_rejects_any_smuggled_view_or_cost_authority_chirho() {
    let classifier_error_chirho = viewer_bound_response_chirho(classified_read_chirho(
        ProjectionReadOutcomeChirho::RefusedChirho(
            FollowerReadRefusalChirho::InvalidDigestEvidenceChirho,
        ),
        Some(br#"{"smuggled_chirho":true}"#.to_vec()),
    ))
    .unwrap_err();
    assert!(classifier_error_chirho
        .to_string()
        .contains("forbidden view bytes"));

    let gate_error_chirho = viewer_bound_response_chirho(ComposedProjectionReadChirho {
        view_bytes_chirho: None,
        verified_cost_class_chirho: Some(ProjectionCostClassChirho::StandingWriteRateChirho),
        outcome_chirho: FollowerServeOutcomeChirho::GateRefusedChirho(
            ServeGateRefusalChirho::ProjectionUnknownChirho,
        ),
    })
    .unwrap_err();
    assert!(gate_error_chirho
        .to_string()
        .contains("unverified view or cost authority"));
}

/// #6087 two-level binding, in-process half: the anonymous missing-context refusal DOWNCASTS to
/// the typed variant, and the missing-port refusal does NOT (both-directions distinctness — a
/// generic conflated error fails this pin from either side).
#[test]
fn missing_viewer_context_refusal_is_typed_and_distinct_chirho() {
    struct UnreachablePortChirho;
    impl PublishedProjectionReadPortChirho for UnreachablePortChirho {
        fn read_published_projection_chirho(
            &self,
            _request_chirho: &PublishedProjectionReadRequestChirho<'_>,
        ) -> anyhow::Result<ComposedProjectionReadChirho> {
            unreachable!("the refusal must fire before any port call")
        }
    }
    let capability_chirho = CapabilityChirho::QueryChirho {
        caller_chirho: "test-chirho".to_string(),
        prefix_chirho: "credits-balance-chirho".to_string(),
        max_rows_chirho: 8,
    };
    let missing_context_chirho = run_published_projection_read_chirho(
        Some(&UnreachablePortChirho),
        &capability_chirho,
        b"{}",
        None,
    )
    .unwrap_err();
    assert!(missing_context_chirho
        .downcast_ref::<PublishedProjectionReadRefusalChirho>()
        .is_some());
    assert!(missing_context_chirho
        .to_string()
        .contains("missing-viewer-context-refusal-chirho"));

    let context_chirho = RequestContextChirho {
        user_principal_chirho: "user/aaaaaaaaaaaaaaaa".to_string(),
        app_chirho: "credits-demo-chirho".to_string(),
        owner_principal_chirho: "owner/bbbbbbbbbbbbbbbb".to_string(),
        client_id_chirho: "client-chirho".to_string(),
        token_hash_chirho: "hash-chirho".to_string(),
        price_book_chirho: None,
        billing_policy_chirho: None,
        key_limit_chirho: None,
    };
    let missing_port_chirho = run_published_projection_read_chirho(
        None,
        &capability_chirho,
        b"{}",
        Some(&context_chirho),
    )
    .unwrap_err();
    assert!(missing_port_chirho
        .downcast_ref::<PublishedProjectionReadRefusalChirho>()
        .is_none());
    assert!(missing_port_chirho
        .downcast_ref::<LegacyMoneyRoadRefusedChirho>()
        .is_some());
}
