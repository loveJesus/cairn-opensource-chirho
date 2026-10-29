// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use cairn_ledger_model_chirho::{ids_chirho::DigestChirho, record_chirho::HlcChirho};
use cairn_model_privacy_chirho::PrivacyClassChirho;

const GOLDEN_DESCRIPTOR_BYTES_CHIRHO: &str = "{\"schema_chirho\":\"ledger-projection-descriptor-v1-chirho\",\"name_chirho\":\"account-balances-chirho\",\"source_families_chirho\":[{\"family_id_chirho\":\"accounts-chirho\",\"source_schema_ref_chirho\":\"1111111111111111111111111111111111111111111111111111111111111111\"}],\"fold_fn_ref_chirho\":\"2222222222222222222222222222222222222222222222222222222222222222\",\"staleness_contract_chirho\":{\"max_owner_hlc_lag_ms_chirho\":5000,\"read_policy_chirho\":\"refuse-when-stale-chirho\"},\"cost_class_chirho\":\"standing-write-rate-chirho\",\"privacy_floor_chirho\":\"direct-chirho\",\"privacy_floor_evidence_ref_chirho\":\"1142dfe6e890847161aafc5563d63b5af9772b48216c13124e6226545514a8a2\",\"rebuild_law_chirho\":\"drop-and-refold-chirho\"}";
const GOLDEN_DESCRIPTOR_DIGEST_CHIRHO: &str =
    "7b424e1ba33ab10c2834efc7726a53022176d640beb6fecddc642f4f32a5d573";

fn digest_chirho(byte_chirho: char) -> DigestChirho {
    DigestChirho(std::iter::repeat_n(byte_chirho, 64).collect())
}

fn verified_source_chirho(
    family_chirho: &str,
    floor_chirho: PrivacyClassChirho,
) -> VerifiedProjectionSourceChirho {
    VerifiedProjectionSourceChirho {
        binding_chirho: ProjectionSourceBindingChirho {
            family_id_chirho: family_chirho.into(),
            source_schema_ref_chirho: digest_chirho('1'),
        },
        privacy_floor_chirho: floor_chirho,
        privacy_evidence_ref_chirho: digest_chirho('3'),
    }
}

fn descriptor_and_sources_chirho() -> (
    ProjectionDescriptorChirho,
    Vec<VerifiedProjectionSourceChirho>,
) {
    let sources_chirho = vec![verified_source_chirho(
        "accounts-chirho",
        PrivacyClassChirho::DirectChirho,
    )];
    let privacy_ref_chirho =
        derive_projection_privacy_evidence_ref_chirho(&sources_chirho).unwrap();
    (
        ProjectionDescriptorChirho {
            schema_chirho: PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO.into(),
            name_chirho: "account-balances-chirho".into(),
            source_families_chirho: sources_chirho
                .iter()
                .map(|source_chirho| source_chirho.binding_chirho.clone())
                .collect(),
            fold_fn_ref_chirho: digest_chirho('2'),
            staleness_contract_chirho: StalenessContractChirho {
                max_owner_hlc_lag_ms_chirho: 5_000,
                read_policy_chirho: ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
            },
            cost_class_chirho: ProjectionCostClassChirho::StandingWriteRateChirho,
            privacy_floor_chirho: PrivacyClassChirho::DirectChirho,
            privacy_floor_evidence_ref_chirho: privacy_ref_chirho,
            rebuild_law_chirho: ProjectionRebuildLawChirho::DropAndRefoldChirho,
        },
        sources_chirho,
    )
}

fn build_verified_descriptor_chirho(
    max_lag_ms_chirho: u64,
    read_policy_chirho: ProjectionReadPolicyChirho,
) -> VerifiedProjectionDescriptorChirho {
    let (mut descriptor_chirho, sources_chirho) = descriptor_and_sources_chirho();
    descriptor_chirho
        .staleness_contract_chirho
        .max_owner_hlc_lag_ms_chirho = max_lag_ms_chirho;
    descriptor_chirho
        .staleness_contract_chirho
        .read_policy_chirho = read_policy_chirho;
    verify_projection_descriptor_chirho(descriptor_chirho, &sources_chirho).unwrap()
}

#[test]
fn projection_descriptor_wire_and_digest_are_literal_pins_chirho() {
    let (descriptor_chirho, sources_chirho) = descriptor_and_sources_chirho();
    validate_projection_descriptor_against_verified_sources_chirho(
        &descriptor_chirho,
        &sources_chirho,
    )
    .unwrap();
    let bytes_chirho = projection_descriptor_bytes_chirho(&descriptor_chirho).unwrap();
    assert_eq!(
        std::str::from_utf8(&bytes_chirho).unwrap(),
        GOLDEN_DESCRIPTOR_BYTES_CHIRHO
    );
    assert_eq!(
        projection_descriptor_digest_chirho(&descriptor_chirho)
            .unwrap()
            .0,
        GOLDEN_DESCRIPTOR_DIGEST_CHIRHO
    );
    assert_eq!(
        parse_canonical_projection_descriptor_chirho(&bytes_chirho).unwrap(),
        descriptor_chirho
    );
}

#[test]
fn projection_descriptor_parser_rejects_malleated_or_unknown_bytes_chirho() {
    let (descriptor_chirho, _) = descriptor_and_sources_chirho();
    let bytes_chirho = projection_descriptor_bytes_chirho(&descriptor_chirho).unwrap();
    let text_chirho = std::str::from_utf8(&bytes_chirho).unwrap();

    let spaced_chirho = format!(" {text_chirho}");
    assert!(parse_canonical_projection_descriptor_chirho(spaced_chirho.as_bytes()).is_err());

    let reordered_chirho = text_chirho.replacen(
        r#"{"schema_chirho":"ledger-projection-descriptor-v1-chirho","name_chirho":"account-balances-chirho""#,
        r#"{"name_chirho":"account-balances-chirho","schema_chirho":"ledger-projection-descriptor-v1-chirho""#,
        1,
    );
    assert!(parse_canonical_projection_descriptor_chirho(reordered_chirho.as_bytes()).is_err());

    let unknown_chirho = text_chirho.replacen(
        r#"{"schema_chirho""#,
        r#"{"unknown_chirho":1,"schema_chirho""#,
        1,
    );
    assert!(parse_canonical_projection_descriptor_chirho(unknown_chirho.as_bytes()).is_err());

    let duplicate_schema_chirho = text_chirho.replacen(
        r#"{"schema_chirho":"ledger-projection-descriptor-v1-chirho""#,
        r#"{"schema_chirho":"ledger-projection-descriptor-v1-chirho","schema_chirho":"ledger-projection-descriptor-v1-chirho""#,
        1,
    );
    assert!(
        parse_canonical_projection_descriptor_chirho(duplicate_schema_chirho.as_bytes()).is_err()
    );
}

#[test]
fn projection_source_set_is_exact_sorted_and_duplicate_safe_chirho() {
    let (mut descriptor_chirho, sources_chirho) = descriptor_and_sources_chirho();
    descriptor_chirho
        .source_families_chirho
        .push(ProjectionSourceBindingChirho {
            family_id_chirho: "accounts-chirho".into(),
            source_schema_ref_chirho: digest_chirho('1'),
        });
    assert!(validate_projection_descriptor_chirho(&descriptor_chirho).is_err());

    let (descriptor_chirho, _) = descriptor_and_sources_chirho();
    assert!(
        validate_projection_descriptor_against_verified_sources_chirho(&descriptor_chirho, &[])
            .is_err()
    );

    let mut extra_sources_chirho = sources_chirho;
    extra_sources_chirho.push(verified_source_chirho(
        "other-chirho",
        PrivacyClassChirho::SafeChirho,
    ));
    assert!(
        validate_projection_descriptor_against_verified_sources_chirho(
            &descriptor_chirho,
            &extra_sources_chirho
        )
        .is_err()
    );
}

#[test]
fn projection_cannot_launder_a_private_source_floor_chirho() {
    let (mut descriptor_chirho, sources_chirho) = descriptor_and_sources_chirho();
    descriptor_chirho.privacy_floor_chirho = PrivacyClassChirho::AnalyticalChirho;
    assert!(
        validate_projection_descriptor_against_verified_sources_chirho(
            &descriptor_chirho,
            &sources_chirho
        )
        .is_err()
    );

    descriptor_chirho.privacy_floor_chirho = PrivacyClassChirho::DirectChirho;
    descriptor_chirho.privacy_floor_evidence_ref_chirho = digest_chirho('9');
    assert!(
        validate_projection_descriptor_against_verified_sources_chirho(
            &descriptor_chirho,
            &sources_chirho
        )
        .is_err()
    );
}

fn view_and_cut_chirho(
    view_seq_chirho: u64,
    view_ms_chirho: u64,
    head_seq_chirho: u64,
    head_ms_chirho: u64,
    descriptor_ref_chirho: &DigestChirho,
) -> (
    PublishedProjectionViewChirho,
    VerifiedProjectionReadCutChirho,
) {
    let same_head_chirho = view_seq_chirho == head_seq_chirho;
    let view_chirho = PublishedProjectionViewChirho {
        descriptor_ref_chirho: descriptor_ref_chirho.clone(),
        watermark_chirho: ProjectionWatermarkChirho {
            source_family_id_chirho: "accounts-chirho".into(),
            source_seq_chirho: view_seq_chirho,
            source_hlc_chirho: HlcChirho {
                physical_ms_chirho: view_ms_chirho,
                logical_chirho: 0,
            },
            signed_prefix_digest_chirho: digest_chirho('4'),
        },
        state_digest_chirho: digest_chirho('5'),
    };
    let verified_cut_chirho = VerifiedProjectionReadCutChirho {
        descriptor_ref_chirho: view_chirho.descriptor_ref_chirho.clone(),
        view_prefix_chirho: view_chirho.watermark_chirho.clone(),
        current_head_chirho: VerifiedProjectionSourceHeadChirho {
            source_family_id_chirho: "accounts-chirho".into(),
            source_seq_chirho: head_seq_chirho,
            source_hlc_chirho: HlcChirho {
                physical_ms_chirho: head_ms_chirho,
                logical_chirho: 0,
            },
            signed_prefix_digest_chirho: if same_head_chirho {
                digest_chirho('4')
            } else {
                digest_chirho('6')
            },
        },
    };
    (view_chirho, verified_cut_chirho)
}

#[test]
fn follower_read_enforces_fresh_refuse_and_typed_degraded_outcomes_chirho() {
    let verified_descriptor_chirho =
        build_verified_descriptor_chirho(5, ProjectionReadPolicyChirho::RefuseWhenStaleChirho);
    let (view_chirho, cut_chirho) =
        view_and_cut_chirho(2, 100, 3, 104, verified_descriptor_chirho.digest_chirho());
    assert!(matches!(
        classify_follower_read_chirho(&view_chirho, &cut_chirho, &verified_descriptor_chirho),
        ProjectionReadOutcomeChirho::FreshChirho {
            lag_ms_chirho: 4,
            ..
        }
    ));

    let verified_descriptor_chirho =
        build_verified_descriptor_chirho(3, ProjectionReadPolicyChirho::RefuseWhenStaleChirho);
    let (view_chirho, cut_chirho) =
        view_and_cut_chirho(2, 100, 3, 104, verified_descriptor_chirho.digest_chirho());
    assert_eq!(
        classify_follower_read_chirho(&view_chirho, &cut_chirho, &verified_descriptor_chirho),
        ProjectionReadOutcomeChirho::RefusedChirho(
            FollowerReadRefusalChirho::StaleBeyondContractChirho {
                lag_ms_chirho: 4,
                max_lag_ms_chirho: 3,
            }
        )
    );

    let verified_descriptor_chirho =
        build_verified_descriptor_chirho(3, ProjectionReadPolicyChirho::ServeDegradedWithLagChirho);
    let (view_chirho, cut_chirho) =
        view_and_cut_chirho(2, 100, 3, 104, verified_descriptor_chirho.digest_chirho());
    assert!(matches!(
        classify_follower_read_chirho(&view_chirho, &cut_chirho, &verified_descriptor_chirho),
        ProjectionReadOutcomeChirho::DegradedChirho {
            lag_ms_chirho: 4,
            max_lag_ms_chirho: 3,
            ..
        }
    ));
}

#[test]
fn follower_read_refuses_read_ahead_and_equal_seq_digest_divergence_chirho() {
    let verified_descriptor_chirho =
        build_verified_descriptor_chirho(5, ProjectionReadPolicyChirho::RefuseWhenStaleChirho);
    let (view_chirho, cut_chirho) =
        view_and_cut_chirho(4, 104, 3, 103, verified_descriptor_chirho.digest_chirho());
    assert_eq!(
        classify_follower_read_chirho(&view_chirho, &cut_chirho, &verified_descriptor_chirho),
        ProjectionReadOutcomeChirho::RefusedChirho(
            FollowerReadRefusalChirho::WatermarkBeyondVerifiedPrefixChirho
        )
    );

    let (view_chirho, mut cut_chirho) =
        view_and_cut_chirho(3, 103, 3, 103, verified_descriptor_chirho.digest_chirho());
    cut_chirho.current_head_chirho.signed_prefix_digest_chirho = digest_chirho('8');
    assert_eq!(
        classify_follower_read_chirho(&view_chirho, &cut_chirho, &verified_descriptor_chirho),
        ProjectionReadOutcomeChirho::RefusedChirho(
            FollowerReadRefusalChirho::EqualSeqHeadMismatchChirho
        )
    );

    let (view_chirho, mut cut_chirho) =
        view_and_cut_chirho(3, 103, 3, 103, verified_descriptor_chirho.digest_chirho());
    cut_chirho
        .current_head_chirho
        .source_hlc_chirho
        .logical_chirho = 1;
    assert_eq!(
        classify_follower_read_chirho(&view_chirho, &cut_chirho, &verified_descriptor_chirho),
        ProjectionReadOutcomeChirho::RefusedChirho(
            FollowerReadRefusalChirho::EqualSeqHeadMismatchChirho
        )
    );
}

#[test]
fn follower_read_refuses_a_forged_lagged_watermark_digest_chirho() {
    let verified_descriptor_chirho =
        build_verified_descriptor_chirho(50, ProjectionReadPolicyChirho::RefuseWhenStaleChirho);
    let (view_chirho, mut cut_chirho) =
        view_and_cut_chirho(2, 100, 3, 104, verified_descriptor_chirho.digest_chirho());
    cut_chirho.view_prefix_chirho.signed_prefix_digest_chirho = digest_chirho('8');
    assert_eq!(
        classify_follower_read_chirho(&view_chirho, &cut_chirho, &verified_descriptor_chirho),
        ProjectionReadOutcomeChirho::RefusedChirho(
            FollowerReadRefusalChirho::ViewWatermarkEvidenceMismatchChirho
        )
    );
}

#[test]
fn follower_read_refuses_a_view_from_the_wrong_descriptor_chirho() {
    let verified_descriptor_chirho =
        build_verified_descriptor_chirho(50, ProjectionReadPolicyChirho::RefuseWhenStaleChirho);
    let (mut view_chirho, cut_chirho) =
        view_and_cut_chirho(2, 100, 3, 104, verified_descriptor_chirho.digest_chirho());
    view_chirho.descriptor_ref_chirho = digest_chirho('9');
    assert_eq!(
        classify_follower_read_chirho(&view_chirho, &cut_chirho, &verified_descriptor_chirho),
        ProjectionReadOutcomeChirho::RefusedChirho(
            FollowerReadRefusalChirho::DescriptorIdentityMismatchChirho
        )
    );
}

#[test]
fn follower_read_refuses_unregistered_or_mismatched_source_families_chirho() {
    let verified_descriptor_chirho =
        build_verified_descriptor_chirho(50, ProjectionReadPolicyChirho::RefuseWhenStaleChirho);
    let (view_chirho, mut cut_chirho) =
        view_and_cut_chirho(2, 100, 3, 104, verified_descriptor_chirho.digest_chirho());
    cut_chirho.current_head_chirho.source_family_id_chirho = "other-chirho".into();
    assert_eq!(
        classify_follower_read_chirho(&view_chirho, &cut_chirho, &verified_descriptor_chirho),
        ProjectionReadOutcomeChirho::RefusedChirho(
            FollowerReadRefusalChirho::SourceFamilyMismatchChirho
        )
    );

    let (mut view_chirho, mut cut_chirho) =
        view_and_cut_chirho(2, 100, 3, 104, verified_descriptor_chirho.digest_chirho());
    view_chirho.watermark_chirho.source_family_id_chirho = "other-chirho".into();
    cut_chirho.view_prefix_chirho = view_chirho.watermark_chirho.clone();
    cut_chirho.current_head_chirho.source_family_id_chirho = "other-chirho".into();
    assert_eq!(
        classify_follower_read_chirho(&view_chirho, &cut_chirho, &verified_descriptor_chirho),
        ProjectionReadOutcomeChirho::RefusedChirho(
            FollowerReadRefusalChirho::SourceFamilyMismatchChirho
        )
    );
}

#[test]
fn follower_read_refuses_invalid_digest_and_hlc_read_ahead_chirho() {
    let verified_descriptor_chirho =
        build_verified_descriptor_chirho(50, ProjectionReadPolicyChirho::RefuseWhenStaleChirho);
    let (mut view_chirho, cut_chirho) =
        view_and_cut_chirho(2, 100, 3, 104, verified_descriptor_chirho.digest_chirho());
    view_chirho.state_digest_chirho = DigestChirho("invalid-chirho".into());
    assert_eq!(
        classify_follower_read_chirho(&view_chirho, &cut_chirho, &verified_descriptor_chirho),
        ProjectionReadOutcomeChirho::RefusedChirho(
            FollowerReadRefusalChirho::InvalidDigestEvidenceChirho
        )
    );

    let (view_chirho, cut_chirho) =
        view_and_cut_chirho(2, 105, 3, 104, verified_descriptor_chirho.digest_chirho());
    assert_eq!(
        classify_follower_read_chirho(&view_chirho, &cut_chirho, &verified_descriptor_chirho),
        ProjectionReadOutcomeChirho::RefusedChirho(
            FollowerReadRefusalChirho::WatermarkHlcBeyondVerifiedHeadChirho
        )
    );
}

#[test]
#[ignore = "reviewed wire regeneration only"]
fn regenerate_projection_descriptor_golden_chirho() {
    let (descriptor_chirho, _) = descriptor_and_sources_chirho();
    eprintln!(
        "bytes_chirho={}\ndigest_chirho={}",
        String::from_utf8(projection_descriptor_bytes_chirho(&descriptor_chirho).unwrap()).unwrap(),
        projection_descriptor_digest_chirho(&descriptor_chirho)
            .unwrap()
            .0
    );
}
