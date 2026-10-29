// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use crate::{
    inspect_host_ledger_signer_custody_chirho, verify_host_ledger_config_custody_chirho,
    ClosedMintBurnAuthorityChirho, FsLedgerStorageChirho, FsMonitorEvidenceSinkChirho,
    HostLedgerAuthorityRefusalChirho, HostLedgerConfigCustodyRefusalChirho,
    HostLedgerSignerRefusalChirho, HostLedgerSignerSecretRefsChirho, HostLedgerSignersChirho,
    HostLedgerStorageRefusalChirho, LedgerSignerRoleChirho, PinnedKindIssuerVerifierChirho,
    PlatformPolicyMintAuthorityChirho, StaticClusterMembershipChirho, SystemLedgerClockChirho,
};
use cairn_config_chirho::config_chirho::LedgerHostIssuerPinConfigChirho;
use cairn_effect_commit_chirho::intent_chirho::{
    EffectIntentSignerPortChirho, EFFECT_INTENT_SCHEMA_V1_CHIRHO,
};
use cairn_effect_commit_chirho::minimal_warrant_chirho::MINIMAL_EFFECT_WARRANT_SCHEMA_V1_CHIRHO;
use cairn_effect_commit_chirho::terminal_chirho::{
    EffectTerminalSignerPortChirho, EFFECT_TERMINAL_OUTCOME_SCHEMA_V1_CHIRHO,
};
use cairn_kind_registry_chirho::chain_chirho::{
    IssuerVerifyViewChirho, KindProjectionChirho, VerifiedRegistryChirho,
};
use cairn_kind_registry_chirho::record_chirho::{
    KindPolicyBodyChirho, MintAuthorityRecordChirho, KIND_REGISTRY_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_log_chirho::admission_chirho::{
    AuthorityVerdictChirho, AuthorityVerifierViewChirho, KindRegistryViewChirho,
    KindResolutionChirho, MembershipStatusChirho, MembershipViewChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{
    JournalErrorChirho, JournalPortsChirho, LedgerJournalChirho,
};
use cairn_ledger_log_chirho::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerClockPortChirho, LedgerSignerPortChirho,
    LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_model_chirho::asset_op_chirho::RoundingChirho;
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, ClusterIdChirho, DigestChirho,
};
use cairn_ledger_model_chirho::ShardEpochChirho;
use cairn_ledger_read_model_chirho::registry_chirho::PROJECTION_REGISTRY_RECORD_SCHEMA_V1_CHIRHO;
use cairn_secret_chirho::secret_chirho::{secret_ref_chirho, set_secret_chirho};
use ed25519_dalek::{Signer, SigningKey};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

mod effect_warrant_publisher_tests_chirho;
mod elected_authority_tests_chirho;
mod reconciliation_manifest_plan_tests_chirho;
mod reconciliation_store_durability_arms_chirho;
mod reconciliation_store_tests_chirho;
pub(crate) mod reconciliation_witness_tests_chirho;
mod resident_adoption_tests_chirho;
mod resident_authority_tests_chirho;
pub(crate) use resident_authority_tests_chirho::{
    resident_mint_request_chirho, warm_single_node_elector_chirho,
    with_bound_resident_fixture_chirho, with_unbound_resident_fixture_chirho, ElectorMeshChirho,
};
mod resident_ledger_identity_tests_chirho;
mod shadow_canary_report_tests_chirho;
mod storage_namespace_tests_chirho;
pub(crate) mod test_kind_fence_tests_chirho;

const JOURNAL_SECRET_NAME_CHIRHO: &str = "ledger-journal-key-chirho";
const CONFIG_SECRET_NAME_CHIRHO: &str = "ledger-config-key-chirho";
const FEEDER_SECRET_NAME_CHIRHO: &str = "ledger-feeder-key-chirho";
const KIND_ROOT_SECRET_NAME_CHIRHO: &str = "ledger-kind-root-key-chirho";
const EFFECT_INTENT_SECRET_NAME_CHIRHO: &str = "effect-intent-key-chirho";
const EFFECT_TERMINAL_SECRET_NAME_CHIRHO: &str = "effect-terminal-key-chirho";

pub(crate) fn temp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "cairn-ledger-host-{label_chirho}-{nanos_chirho}-{counter_chirho}"
    ))
}

pub(crate) fn signer_refs_chirho() -> HostLedgerSignerSecretRefsChirho {
    HostLedgerSignerSecretRefsChirho {
        journal_chirho: secret_ref_chirho(JOURNAL_SECRET_NAME_CHIRHO).unwrap(),
        config_chirho: secret_ref_chirho(CONFIG_SECRET_NAME_CHIRHO).unwrap(),
        feeder_chirho: secret_ref_chirho(FEEDER_SECRET_NAME_CHIRHO).unwrap(),
        kind_root_chirho: secret_ref_chirho(KIND_ROOT_SECRET_NAME_CHIRHO).unwrap(),
        effect_intent_chirho: secret_ref_chirho(EFFECT_INTENT_SECRET_NAME_CHIRHO).unwrap(),
        effect_terminal_chirho: secret_ref_chirho(EFFECT_TERMINAL_SECRET_NAME_CHIRHO).unwrap(),
    }
}

fn provision_signers_chirho(root_chirho: &Path) -> HostLedgerSignerSecretRefsChirho {
    set_secret_chirho(root_chirho, JOURNAL_SECRET_NAME_CHIRHO, &[0x11; 32]).unwrap();
    set_secret_chirho(root_chirho, CONFIG_SECRET_NAME_CHIRHO, &[0x22; 32]).unwrap();
    set_secret_chirho(root_chirho, FEEDER_SECRET_NAME_CHIRHO, &[0x33; 32]).unwrap();
    set_secret_chirho(root_chirho, KIND_ROOT_SECRET_NAME_CHIRHO, &[0x44; 32]).unwrap();
    set_secret_chirho(root_chirho, EFFECT_INTENT_SECRET_NAME_CHIRHO, &[0x55; 32]).unwrap();
    set_secret_chirho(root_chirho, EFFECT_TERMINAL_SECRET_NAME_CHIRHO, &[0x66; 32]).unwrap();
    signer_refs_chirho()
}

fn snapshot_files_chirho(root_chirho: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut snapshot_chirho = BTreeMap::new();
    let mut pending_chirho = vec![root_chirho.to_path_buf()];
    while let Some(path_chirho) = pending_chirho.pop() {
        if !path_chirho.exists() {
            continue;
        }
        if path_chirho.is_dir() {
            let mut children_chirho = fs::read_dir(&path_chirho)
                .unwrap()
                .map(|entry_chirho| entry_chirho.unwrap().path())
                .collect::<Vec<_>>();
            children_chirho.sort();
            pending_chirho.extend(children_chirho);
        } else if path_chirho.is_file() {
            snapshot_chirho.insert(
                path_chirho.strip_prefix(root_chirho).unwrap().to_path_buf(),
                fs::read(path_chirho).unwrap(),
            );
        }
    }
    snapshot_chirho
}

fn hex_bytes_chirho(bytes_chirho: &[u8]) -> String {
    let mut encoded_chirho = String::with_capacity(bytes_chirho.len() * 2);
    for byte_chirho in bytes_chirho {
        use std::fmt::Write;
        write!(&mut encoded_chirho, "{byte_chirho:02x}").unwrap();
    }
    encoded_chirho
}

#[test]
fn role_bound_signers_load_without_writes_and_refuse_cross_role_chirho() {
    let root_chirho = temp_root_chirho("role-bound");
    let refs_chirho = provision_signers_chirho(&root_chirho);
    let before_chirho = snapshot_files_chirho(&root_chirho);
    let signers_chirho =
        HostLedgerSignersChirho::load_existing_chirho(&root_chirho, &refs_chirho).unwrap();
    assert_eq!(snapshot_files_chirho(&root_chirho), before_chirho);

    let journal_line_chirho = r#"{"schema_chirho":"ledger-record-v1-chirho","probe_chirho":1}"#;
    let config_line_chirho = format!(
        r#"{{"schema_chirho":"{PROJECTION_REGISTRY_RECORD_SCHEMA_V1_CHIRHO}","probe_chirho":1}}"#
    );
    let feeder_line_chirho =
        r#"{"schema_chirho":"ledger-projection-follow-receipt-v1-chirho","probe_chirho":1}"#;
    let kind_line_chirho =
        format!(r#"{{"schema_chirho":"{KIND_REGISTRY_SCHEMA_V1_CHIRHO}","probe_chirho":1}}"#);
    let intent_line_chirho =
        format!(r#"{{"schema_chirho":"{EFFECT_INTENT_SCHEMA_V1_CHIRHO}","probe_chirho":1}}"#);
    let minimal_warrant_line_chirho = format!(
        r#"{{"schema_chirho":"{MINIMAL_EFFECT_WARRANT_SCHEMA_V1_CHIRHO}","probe_chirho":1}}"#
    );
    let terminal_line_chirho = format!(
        r#"{{"schema_chirho":"{EFFECT_TERMINAL_OUTCOME_SCHEMA_V1_CHIRHO}","probe_chirho":1}}"#
    );

    let journal_sig_chirho =
        LedgerSignerPortChirho::sign_chirho(&signers_chirho.journal_chirho, journal_line_chirho)
            .unwrap();
    assert!(LedgerSignerPortChirho::verify_chirho(
        &signers_chirho.journal_chirho,
        journal_line_chirho,
        &journal_sig_chirho,
    ));
    let config_sig_chirho =
        LedgerSignerPortChirho::sign_chirho(&signers_chirho.config_chirho, &config_line_chirho)
            .unwrap();
    assert!(LedgerSignerPortChirho::verify_chirho(
        &signers_chirho.config_chirho,
        &config_line_chirho,
        &config_sig_chirho,
    ));
    let feeder_sig_chirho =
        LedgerSignerPortChirho::sign_chirho(&signers_chirho.feeder_chirho, feeder_line_chirho)
            .unwrap();
    assert!(LedgerSignerPortChirho::verify_chirho(
        &signers_chirho.feeder_chirho,
        feeder_line_chirho,
        &feeder_sig_chirho,
    ));
    let kind_sig_chirho =
        LedgerSignerPortChirho::sign_chirho(&signers_chirho.kind_root_chirho, &kind_line_chirho)
            .unwrap();
    assert!(LedgerSignerPortChirho::verify_chirho(
        &signers_chirho.kind_root_chirho,
        &kind_line_chirho,
        &kind_sig_chirho,
    ));
    let intent_sig_chirho = EffectIntentSignerPortChirho::sign_chirho(
        &signers_chirho.effect_intent_chirho,
        &intent_line_chirho,
    )
    .unwrap();
    assert!(EffectIntentSignerPortChirho::verify_chirho(
        &signers_chirho.effect_intent_chirho,
        &intent_line_chirho,
        &intent_sig_chirho,
    ));
    let minimal_warrant_sig_chirho = EffectIntentSignerPortChirho::sign_chirho(
        &signers_chirho.effect_intent_chirho,
        &minimal_warrant_line_chirho,
    )
    .unwrap();
    assert!(EffectIntentSignerPortChirho::verify_chirho(
        &signers_chirho.effect_intent_chirho,
        &minimal_warrant_line_chirho,
        &minimal_warrant_sig_chirho,
    ));
    let terminal_sig_chirho = EffectTerminalSignerPortChirho::sign_chirho(
        &signers_chirho.effect_terminal_chirho,
        &terminal_line_chirho,
    )
    .unwrap();
    assert!(EffectTerminalSignerPortChirho::verify_chirho(
        &signers_chirho.effect_terminal_chirho,
        &terminal_line_chirho,
        &terminal_sig_chirho,
    ));

    let error_chirho =
        LedgerSignerPortChirho::sign_chirho(&signers_chirho.journal_chirho, &config_line_chirho)
            .unwrap_err();
    assert_eq!(
        error_chirho.downcast_ref::<HostLedgerSignerRefusalChirho>(),
        Some(&HostLedgerSignerRefusalChirho::MessageRoleMismatchChirho {
            role_chirho: LedgerSignerRoleChirho::JournalChirho,
        })
    );
    assert!(!LedgerSignerPortChirho::verify_chirho(
        &signers_chirho.journal_chirho,
        &config_line_chirho,
        &config_sig_chirho,
    ));
    assert!(!LedgerSignerPortChirho::verify_chirho(
        &signers_chirho.config_chirho,
        journal_line_chirho,
        &journal_sig_chirho,
    ));
    for error_chirho in [
        LedgerSignerPortChirho::sign_chirho(&signers_chirho.kind_root_chirho, &intent_line_chirho)
            .unwrap_err(),
        EffectIntentSignerPortChirho::sign_chirho(
            &signers_chirho.effect_intent_chirho,
            &terminal_line_chirho,
        )
        .unwrap_err(),
        EffectTerminalSignerPortChirho::sign_chirho(
            &signers_chirho.effect_terminal_chirho,
            &kind_line_chirho,
        )
        .unwrap_err(),
    ] {
        assert!(matches!(
            error_chirho.downcast_ref::<HostLedgerSignerRefusalChirho>(),
            Some(HostLedgerSignerRefusalChirho::MessageRoleMismatchChirho { .. })
        ));
    }
    let foreign_role_error_chirho = EffectTerminalSignerPortChirho::sign_chirho(
        &signers_chirho.effect_terminal_chirho,
        &minimal_warrant_line_chirho,
    )
    .unwrap_err();
    assert!(matches!(
        foreign_role_error_chirho.downcast_ref::<HostLedgerSignerRefusalChirho>(),
        Some(HostLedgerSignerRefusalChirho::MessageRoleMismatchChirho {
            role_chirho: LedgerSignerRoleChirho::EffectTerminalChirho,
        })
    ));
    let _ = fs::remove_dir_all(root_chirho);
}

#[test]
fn signer_loading_refuses_missing_malformed_zero_and_duplicate_identities_chirho() {
    let missing_root_chirho = temp_root_chirho("missing");
    fs::create_dir_all(&missing_root_chirho).unwrap();
    let missing_error_chirho =
        HostLedgerSignersChirho::load_existing_chirho(&missing_root_chirho, &signer_refs_chirho())
            .unwrap_err();
    assert!(matches!(
        missing_error_chirho.downcast_ref::<HostLedgerSignerRefusalChirho>(),
        Some(HostLedgerSignerRefusalChirho::SecretUnavailableChirho { .. })
    ));
    let _ = fs::remove_dir_all(missing_root_chirho);

    let malformed_root_chirho = temp_root_chirho("malformed");
    let refs_chirho = signer_refs_chirho();
    set_secret_chirho(
        &malformed_root_chirho,
        JOURNAL_SECRET_NAME_CHIRHO,
        &[0x11; 31],
    )
    .unwrap();
    set_secret_chirho(
        &malformed_root_chirho,
        CONFIG_SECRET_NAME_CHIRHO,
        &[0x22; 32],
    )
    .unwrap();
    set_secret_chirho(
        &malformed_root_chirho,
        FEEDER_SECRET_NAME_CHIRHO,
        &[0x33; 32],
    )
    .unwrap();
    set_secret_chirho(
        &malformed_root_chirho,
        KIND_ROOT_SECRET_NAME_CHIRHO,
        &[0x44; 32],
    )
    .unwrap();
    set_secret_chirho(
        &malformed_root_chirho,
        EFFECT_INTENT_SECRET_NAME_CHIRHO,
        &[0x55; 32],
    )
    .unwrap();
    set_secret_chirho(
        &malformed_root_chirho,
        EFFECT_TERMINAL_SECRET_NAME_CHIRHO,
        &[0x66; 32],
    )
    .unwrap();
    let malformed_error_chirho =
        HostLedgerSignersChirho::load_existing_chirho(&malformed_root_chirho, &refs_chirho)
            .unwrap_err();
    assert!(matches!(
        malformed_error_chirho.downcast_ref::<HostLedgerSignerRefusalChirho>(),
        Some(HostLedgerSignerRefusalChirho::SecretLengthChirho {
            actual_bytes_chirho: 31,
            ..
        })
    ));
    let _ = fs::remove_dir_all(malformed_root_chirho);

    let zero_root_chirho = temp_root_chirho("zero");
    set_secret_chirho(&zero_root_chirho, JOURNAL_SECRET_NAME_CHIRHO, &[0; 32]).unwrap();
    set_secret_chirho(&zero_root_chirho, CONFIG_SECRET_NAME_CHIRHO, &[0x22; 32]).unwrap();
    set_secret_chirho(&zero_root_chirho, FEEDER_SECRET_NAME_CHIRHO, &[0x33; 32]).unwrap();
    set_secret_chirho(&zero_root_chirho, KIND_ROOT_SECRET_NAME_CHIRHO, &[0x44; 32]).unwrap();
    set_secret_chirho(
        &zero_root_chirho,
        EFFECT_INTENT_SECRET_NAME_CHIRHO,
        &[0x55; 32],
    )
    .unwrap();
    set_secret_chirho(
        &zero_root_chirho,
        EFFECT_TERMINAL_SECRET_NAME_CHIRHO,
        &[0x66; 32],
    )
    .unwrap();
    let zero_error_chirho =
        HostLedgerSignersChirho::load_existing_chirho(&zero_root_chirho, &refs_chirho).unwrap_err();
    assert!(matches!(
        zero_error_chirho.downcast_ref::<HostLedgerSignerRefusalChirho>(),
        Some(HostLedgerSignerRefusalChirho::AllZeroSecretChirho { .. })
    ));
    let _ = fs::remove_dir_all(zero_root_chirho);

    let duplicate_root_chirho = temp_root_chirho("duplicate");
    set_secret_chirho(
        &duplicate_root_chirho,
        JOURNAL_SECRET_NAME_CHIRHO,
        &[0x44; 32],
    )
    .unwrap();
    set_secret_chirho(
        &duplicate_root_chirho,
        CONFIG_SECRET_NAME_CHIRHO,
        &[0x44; 32],
    )
    .unwrap();
    set_secret_chirho(
        &duplicate_root_chirho,
        FEEDER_SECRET_NAME_CHIRHO,
        &[0x55; 32],
    )
    .unwrap();
    set_secret_chirho(
        &duplicate_root_chirho,
        KIND_ROOT_SECRET_NAME_CHIRHO,
        &[0x66; 32],
    )
    .unwrap();
    set_secret_chirho(
        &duplicate_root_chirho,
        EFFECT_INTENT_SECRET_NAME_CHIRHO,
        &[0x77; 32],
    )
    .unwrap();
    set_secret_chirho(
        &duplicate_root_chirho,
        EFFECT_TERMINAL_SECRET_NAME_CHIRHO,
        &[0x88; 32],
    )
    .unwrap();
    let duplicate_error_chirho =
        HostLedgerSignersChirho::load_existing_chirho(&duplicate_root_chirho, &refs_chirho)
            .unwrap_err();
    assert_eq!(
        duplicate_error_chirho.downcast_ref::<HostLedgerSignerRefusalChirho>(),
        Some(&HostLedgerSignerRefusalChirho::DuplicateIdentityChirho {
            first_role_chirho: LedgerSignerRoleChirho::JournalChirho,
            second_role_chirho: LedgerSignerRoleChirho::ConfigChirho,
        })
    );
    let _ = fs::remove_dir_all(duplicate_root_chirho);
}

#[test]
fn static_membership_is_exact_nonempty_duplicate_free_and_epoch_pinned_chirho() {
    let member_chirho = AccountIdChirho {
        owner_chirho: "credits-user-chirho".to_owned(),
        kind_id_chirho: AssetKindIdChirho("credits-chirho".to_owned()),
    };
    assert_eq!(
        StaticClusterMembershipChirho::new_chirho(0, Vec::<AccountIdChirho>::new()).unwrap_err(),
        HostLedgerAuthorityRefusalChirho::EmptyMembershipChirho,
    );
    assert!(matches!(
        StaticClusterMembershipChirho::new_chirho(
            0,
            [member_chirho.clone(), member_chirho.clone()]
        ),
        Err(HostLedgerAuthorityRefusalChirho::DuplicateMemberChirho { .. })
    ));
    let membership_chirho =
        StaticClusterMembershipChirho::new_chirho(0, [member_chirho.clone()]).unwrap();
    let elected_chirho = membership_chirho.elected_view_chirho();
    assert!(elected_chirho.shares_roster_with_chirho(&membership_chirho));
    assert_eq!(
        membership_chirho.status_chirho(&member_chirho, 0),
        MembershipStatusChirho::MemberChirho,
    );
    assert_eq!(
        membership_chirho.status_chirho(&member_chirho, 1),
        MembershipStatusChirho::NonMemberChirho,
    );
    let other_kind_chirho = AccountIdChirho {
        owner_chirho: member_chirho.owner_chirho.clone(),
        kind_id_chirho: AssetKindIdChirho("other-kind-chirho".to_owned()),
    };
    assert_eq!(
        membership_chirho.status_chirho(&other_kind_chirho, 0),
        MembershipStatusChirho::NonMemberChirho,
    );
    elected_chirho.rebind_epoch_chirho(9).unwrap();
    assert_eq!(elected_chirho.current_epoch_chirho(), 9);
    assert_eq!(
        elected_chirho.status_chirho(&member_chirho, 9),
        MembershipStatusChirho::MemberChirho,
    );
    assert_eq!(
        elected_chirho.status_chirho(&member_chirho, 0),
        MembershipStatusChirho::NonMemberChirho,
    );
    assert_eq!(
        elected_chirho.rebind_epoch_chirho(8).unwrap_err(),
        HostLedgerAuthorityRefusalChirho::MembershipEpochRegressionChirho {
            current_epoch_chirho: 9,
            requested_epoch_chirho: 8,
        },
    );
}

#[test]
fn issuer_pin_validates_real_ed25519_and_refuses_cross_principal_chirho() {
    let signing_key_chirho = SigningKey::from_bytes(&[0x71; 32]);
    let config_chirho = LedgerHostIssuerPinConfigChirho {
        principal_chirho: "platform-issuer-chirho".to_owned(),
        verifying_key_hex_chirho: hex_bytes_chirho(signing_key_chirho.verifying_key().as_bytes()),
    };
    let verifier_chirho =
        PinnedKindIssuerVerifierChirho::from_config_chirho(&config_chirho).unwrap();
    let content_chirho = r#"{"schema_chirho":"cairn-kind-registry-record-v1-chirho"}"#;
    let signature_chirho = hex_bytes_chirho(
        &signing_key_chirho
            .sign(content_chirho.as_bytes())
            .to_bytes(),
    );
    assert!(verifier_chirho.verify_issuer_chirho(
        "platform-issuer-chirho",
        content_chirho,
        &signature_chirho,
    ));
    assert!(!verifier_chirho.verify_issuer_chirho(
        "other-issuer-chirho",
        content_chirho,
        &signature_chirho,
    ));
    let debug_chirho = format!("{verifier_chirho:?}");
    assert!(debug_chirho.contains("<pinned-redacted-chirho>"));
    assert!(!debug_chirho.contains(&config_chirho.verifying_key_hex_chirho));

    let malformed_chirho = LedgerHostIssuerPinConfigChirho {
        principal_chirho: "platform-issuer-chirho".to_owned(),
        verifying_key_hex_chirho: "00".repeat(32),
    };
    assert_eq!(
        PinnedKindIssuerVerifierChirho::from_config_chirho(&malformed_chirho).unwrap_err(),
        HostLedgerAuthorityRefusalChirho::InvalidIssuerKeyChirho,
    );
    let invalid_point_chirho = LedgerHostIssuerPinConfigChirho {
        principal_chirho: "platform-issuer-chirho".to_owned(),
        verifying_key_hex_chirho: "02".repeat(32),
    };
    assert_eq!(
        PinnedKindIssuerVerifierChirho::from_config_chirho(&invalid_point_chirho).unwrap_err(),
        HostLedgerAuthorityRefusalChirho::InvalidIssuerKeyChirho,
    );
}

fn policy_chirho(mint_authority_chirho: MintAuthorityRecordChirho) -> KindPolicyBodyChirho {
    KindPolicyBodyChirho {
        unit_chirho: "credit-chirho".to_owned(),
        precision_chirho: 0,
        mint_authority_chirho,
        rounding_chirho: RoundingChirho::ExactChirho,
        shard_attachment_chirho: "credits-shard-chirho".to_owned(),
        settlement_owner_chirho: Some("platform-chirho".to_owned()),
        idempotency_window_chirho: None,
    }
}

pub(crate) fn authority_registry_chirho() -> VerifiedRegistryChirho {
    let credits_ref_chirho = AssetKindRefChirho(DigestChirho("11".repeat(32)));
    let old_credits_ref_chirho = AssetKindRefChirho(DigestChirho("22".repeat(32)));
    let provider_ref_chirho = AssetKindRefChirho(DigestChirho("33".repeat(32)));
    VerifiedRegistryChirho {
        records_chirho: Vec::new(),
        tail_digest_chirho: DigestChirho("44".repeat(32)),
        kinds_chirho: [
            (
                AssetKindIdChirho("credits-chirho".to_owned()),
                KindProjectionChirho {
                    current_policy_chirho: policy_chirho(
                        MintAuthorityRecordChirho::PlatformPolicyChirho {
                            max_supply_chirho: Some(1_000),
                        },
                    ),
                    current_ref_chirho: credits_ref_chirho,
                    superseded_refs_chirho: [old_credits_ref_chirho].into_iter().collect(),
                },
            ),
            (
                AssetKindIdChirho("money-chirho".to_owned()),
                KindProjectionChirho {
                    current_policy_chirho: policy_chirho(
                        MintAuthorityRecordChirho::ProviderReceiptChirho,
                    ),
                    current_ref_chirho: provider_ref_chirho,
                    superseded_refs_chirho: BTreeSet::new(),
                },
            ),
        ]
        .into_iter()
        .collect(),
    }
}

#[test]
fn platform_policy_mint_authority_is_current_kind_exact_and_burn_closed_chirho() {
    let registry_chirho = authority_registry_chirho();
    let authority_chirho = PlatformPolicyMintAuthorityChirho::new_chirho(&registry_chirho);
    let credits_chirho = AssetKindIdChirho("credits-chirho".to_owned());
    let money_chirho = AssetKindIdChirho("money-chirho".to_owned());
    assert_eq!(
        authority_chirho.verify_mint_chirho(&DigestChirho("11".repeat(32)), &credits_chirho),
        AuthorityVerdictChirho::VerifiedChirho,
    );
    assert_eq!(
        authority_chirho.verify_mint_chirho(&DigestChirho("22".repeat(32)), &credits_chirho),
        AuthorityVerdictChirho::UnverifiedChirho,
    );
    assert_eq!(
        authority_chirho.verify_mint_chirho(&DigestChirho("33".repeat(32)), &credits_chirho),
        AuthorityVerdictChirho::WrongKindChirho,
    );
    assert_eq!(
        authority_chirho.verify_mint_chirho(&DigestChirho("33".repeat(32)), &money_chirho),
        AuthorityVerdictChirho::UnverifiedChirho,
    );
    assert_eq!(
        authority_chirho.verify_burn_chirho(&DigestChirho("11".repeat(32)), &credits_chirho),
        AuthorityVerdictChirho::UnverifiedChirho,
    );
    let closed_chirho = ClosedMintBurnAuthorityChirho;
    assert_eq!(
        closed_chirho.verify_mint_chirho(&DigestChirho("11".repeat(32)), &credits_chirho),
        AuthorityVerdictChirho::UnverifiedChirho,
    );
    assert_eq!(
        closed_chirho.verify_burn_chirho(&DigestChirho("11".repeat(32)), &credits_chirho),
        AuthorityVerdictChirho::UnverifiedChirho,
    );
}

#[test]
fn custody_debug_and_errors_never_emit_key_material_chirho() {
    let root_chirho = temp_root_chirho("redaction");
    let refs_chirho = provision_signers_chirho(&root_chirho);
    let signers_chirho =
        HostLedgerSignersChirho::load_existing_chirho(&root_chirho, &refs_chirho).unwrap();
    let custody_chirho =
        inspect_host_ledger_signer_custody_chirho(&root_chirho, &refs_chirho).unwrap();
    let debug_chirho = format!("{signers_chirho:?}");
    let evidence_chirho = serde_json::to_string(&custody_chirho).unwrap();
    let hostile_line_chirho = format!(
        r#"{{"schema_chirho":"{}","payload_chirho":"{}"}}"#,
        "hostile-message-class-chirho",
        "J".repeat(32)
    );
    let error_text_chirho =
        LedgerSignerPortChirho::sign_chirho(&signers_chirho.journal_chirho, &hostile_line_chirho)
            .unwrap_err()
            .to_string();
    for private_text_chirho in ["J".repeat(32), "\u{11}".repeat(32)] {
        assert!(!debug_chirho.contains(&private_text_chirho));
        assert!(!evidence_chirho.contains(&private_text_chirho));
        assert!(!error_text_chirho.contains(&private_text_chirho));
    }
    assert!(debug_chirho.contains("<redacted-chirho>"));
    assert!(custody_chirho.values_redacted_chirho);
    assert!(custody_chirho.journal_chirho.exact_32_bytes_chirho);
    assert!(custody_chirho.config_chirho.exact_32_bytes_chirho);
    assert!(custody_chirho.feeder_chirho.exact_32_bytes_chirho);
    assert!(custody_chirho.kind_root_chirho.exact_32_bytes_chirho);
    assert!(custody_chirho.effect_intent_chirho.exact_32_bytes_chirho);
    assert!(custody_chirho.effect_terminal_chirho.exact_32_bytes_chirho);
    let _ = fs::remove_dir_all(root_chirho);
}

#[test]
fn config_custody_is_read_only_and_refuses_unsafe_file_postures_chirho() {
    let root_chirho = temp_root_chirho("config-custody");
    let selected_root_chirho = root_chirho.join("selected-root-chirho");
    let config_path_chirho = root_chirho.join("ledger-host-config-chirho.toml");
    fs::create_dir_all(&selected_root_chirho).unwrap();
    fs::write(&config_path_chirho, b"strict-config-chirho").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&config_path_chirho, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let before_verify_chirho = snapshot_files_chirho(&root_chirho);
    verify_host_ledger_config_custody_chirho(&selected_root_chirho, &config_path_chirho).unwrap();
    assert_eq!(snapshot_files_chirho(&root_chirho), before_verify_chirho);

    let directory_path_chirho = root_chirho.join("not-a-config-chirho");
    fs::create_dir_all(&directory_path_chirho).unwrap();
    let directory_error_chirho =
        verify_host_ledger_config_custody_chirho(&selected_root_chirho, &directory_path_chirho)
            .unwrap_err();
    assert_eq!(
        directory_error_chirho.downcast_ref::<HostLedgerConfigCustodyRefusalChirho>(),
        Some(&HostLedgerConfigCustodyRefusalChirho::ConfigNotRegularChirho)
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt};

        fs::set_permissions(&config_path_chirho, fs::Permissions::from_mode(0o644)).unwrap();
        let mode_error_chirho =
            verify_host_ledger_config_custody_chirho(&selected_root_chirho, &config_path_chirho)
                .unwrap_err();
        assert_eq!(
            mode_error_chirho.downcast_ref::<HostLedgerConfigCustodyRefusalChirho>(),
            Some(&HostLedgerConfigCustodyRefusalChirho::ConfigModeTooBroadChirho)
        );

        let symlink_path_chirho = root_chirho.join("linked-config-chirho.toml");
        symlink(&config_path_chirho, &symlink_path_chirho).unwrap();
        let symlink_error_chirho =
            verify_host_ledger_config_custody_chirho(&selected_root_chirho, &symlink_path_chirho)
                .unwrap_err();
        assert_eq!(
            symlink_error_chirho.downcast_ref::<HostLedgerConfigCustodyRefusalChirho>(),
            Some(&HostLedgerConfigCustodyRefusalChirho::ConfigSymlinkChirho)
        );
    }

    let _ = fs::remove_dir_all(root_chirho);
}

#[test]
fn filesystem_storage_round_trips_every_port_primitive_chirho() {
    let root_chirho = temp_root_chirho("storage");
    fs::create_dir_all(&root_chirho).unwrap();
    let before_open_chirho = snapshot_files_chirho(&root_chirho);
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&root_chirho).unwrap();
    assert_eq!(snapshot_files_chirho(&root_chirho), before_open_chirho);

    let born_once_chirho = StoragePathChirho::new_chirho("journals/born-once-chirho.jsonl");
    assert_eq!(
        storage_chirho
            .create_durable_chirho(&born_once_chirho, b"genesis chirho\n")
            .unwrap(),
        CreateDurableOutcomeChirho::CreatedChirho
    );
    assert_eq!(
        storage_chirho
            .create_durable_chirho(&born_once_chirho, b"foreign chirho\n")
            .unwrap(),
        CreateDurableOutcomeChirho::AlreadyExistsChirho
    );
    assert_eq!(
        storage_chirho.read_all_chirho(&born_once_chirho).unwrap(),
        Some(b"genesis chirho\n".to_vec())
    );

    let active_chirho = StoragePathChirho::new_chirho("journals/active-chirho.jsonl");
    storage_chirho
        .atomic_write_chirho(&active_chirho, b"abcdef")
        .unwrap();
    assert_eq!(
        storage_chirho.read_all_chirho(&active_chirho).unwrap(),
        Some(b"abcdef".to_vec())
    );
    assert_eq!(
        storage_chirho.object_len_chirho(&active_chirho).unwrap(),
        Some(6)
    );
    assert_eq!(
        storage_chirho
            .read_exact_range_chirho(&active_chirho, 1, 3)
            .unwrap(),
        b"bcd"
    );
    storage_chirho
        .append_durable_chirho(&active_chirho, b"gh")
        .unwrap();
    storage_chirho
        .truncate_durable_chirho(&active_chirho, 4)
        .unwrap();
    assert_eq!(
        storage_chirho.read_all_chirho(&active_chirho).unwrap(),
        Some(b"abcd".to_vec())
    );

    let sealed_chirho = StoragePathChirho::new_chirho("sealed/segment-0001-chirho");
    storage_chirho
        .rename_chirho(&active_chirho, &sealed_chirho)
        .unwrap();
    assert!(!storage_chirho.exists_chirho(&active_chirho).unwrap());
    assert!(storage_chirho.exists_chirho(&sealed_chirho).unwrap());
    assert_eq!(
        storage_chirho
            .list_chirho(&StoragePathChirho::new_chirho("sealed/"))
            .unwrap(),
        vec![sealed_chirho.clone()]
    );
    storage_chirho.remove_chirho(&sealed_chirho).unwrap();
    storage_chirho.remove_chirho(&sealed_chirho).unwrap();
    assert!(!storage_chirho.exists_chirho(&sealed_chirho).unwrap());
    let _ = fs::remove_dir_all(root_chirho);
}

#[test]
fn filesystem_storage_refuses_hostile_coordinates_and_symlinks_chirho() {
    let root_chirho = temp_root_chirho("hostile-path");
    fs::create_dir_all(&root_chirho).unwrap();
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&root_chirho).unwrap();
    for hostile_chirho in [
        "../outside-chirho",
        "/absolute-chirho",
        "nested//alias-chirho",
        "nested/./alias-chirho",
        "nested\\escape-chirho",
        "pii@example.com",
    ] {
        let error_chirho = storage_chirho
            .exists_chirho(&StoragePathChirho::new_chirho(hostile_chirho))
            .unwrap_err();
        assert_eq!(
            error_chirho.downcast_ref::<HostLedgerStorageRefusalChirho>(),
            Some(&HostLedgerStorageRefusalChirho::UnsafeLogicalPathChirho)
        );
        assert!(!error_chirho.to_string().contains(hostile_chirho));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let outside_chirho = temp_root_chirho("outside");
        fs::create_dir_all(&outside_chirho).unwrap();
        symlink(&outside_chirho, root_chirho.join("linked-chirho")).unwrap();
        let error_chirho = storage_chirho
            .read_all_chirho(&StoragePathChirho::new_chirho(
                "linked-chirho/secret-chirho",
            ))
            .unwrap_err();
        assert_eq!(
            error_chirho.downcast_ref::<HostLedgerStorageRefusalChirho>(),
            Some(&HostLedgerStorageRefusalChirho::SymlinkBoundaryChirho)
        );
        let _ = fs::remove_dir_all(outside_chirho);
    }
    let _ = fs::remove_dir_all(root_chirho);
}

#[test]
fn monitor_evidence_sink_is_disjoint_read_only_at_open_and_operational_only_chirho() {
    let root_chirho = temp_root_chirho("monitor-evidence");
    let ledger_root_chirho = root_chirho.join("ledger-chirho");
    let evidence_root_chirho = root_chirho.join("monitor-ops-chirho");
    fs::create_dir_all(&ledger_root_chirho).unwrap();
    fs::create_dir_all(&evidence_root_chirho).unwrap();
    let ledger_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&ledger_root_chirho).unwrap();
    let before_open_chirho = snapshot_files_chirho(&root_chirho);
    let evidence_sink_chirho = FsMonitorEvidenceSinkChirho::open_existing_disjoint_chirho(
        &ledger_storage_chirho,
        &evidence_root_chirho,
    )
    .unwrap();
    assert_eq!(snapshot_files_chirho(&root_chirho), before_open_chirho);
    assert_eq!(
        evidence_sink_chirho.namespace_root_chirho(),
        evidence_root_chirho.canonicalize().unwrap()
    );

    evidence_sink_chirho
        .append_operational_row_chirho(
            "cycles/conservation-chirho.jsonl",
            br#"{"schema_chirho":"ops-conservation-cycle-v1-chirho"}"#,
        )
        .unwrap();
    assert_eq!(
        fs::read(evidence_root_chirho.join("cycles/conservation-chirho.jsonl")).unwrap(),
        b"{\"schema_chirho\":\"ops-conservation-cycle-v1-chirho\"}\n"
    );
    assert!(!ledger_root_chirho.join("cycles").exists());

    let error_chirho = evidence_sink_chirho
        .append_operational_row_chirho(
            "cycles/forged-chirho.jsonl",
            b"{\"schema_chirho\":\"one-chirho\"}\n{\"schema_chirho\":\"two-chirho\"}",
        )
        .unwrap_err();
    assert_eq!(
        error_chirho.downcast_ref::<HostLedgerStorageRefusalChirho>(),
        Some(&HostLedgerStorageRefusalChirho::InvalidOperationalRowChirho)
    );
    assert!(!evidence_root_chirho
        .join("cycles/forged-chirho.jsonl")
        .exists());
    let _ = fs::remove_dir_all(root_chirho);
}

#[test]
fn monitor_evidence_sink_refuses_equal_or_nested_ledger_namespaces_chirho() {
    let root_chirho = temp_root_chirho("monitor-overlap");
    let ledger_root_chirho = root_chirho.join("ledger-chirho");
    let nested_chirho = ledger_root_chirho.join("ops-chirho");
    fs::create_dir_all(&nested_chirho).unwrap();
    let ledger_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&ledger_root_chirho).unwrap();
    for evidence_root_chirho in [&ledger_root_chirho, &nested_chirho] {
        let error_chirho = FsMonitorEvidenceSinkChirho::open_existing_disjoint_chirho(
            &ledger_storage_chirho,
            evidence_root_chirho,
        )
        .unwrap_err();
        assert_eq!(
            error_chirho.downcast_ref::<HostLedgerStorageRefusalChirho>(),
            Some(&HostLedgerStorageRefusalChirho::OverlappingMonitorNamespaceChirho)
        );
    }
    let _ = fs::remove_dir_all(root_chirho);
}

struct ClosedMembershipChirho;

impl MembershipViewChirho for ClosedMembershipChirho {
    fn status_chirho(
        &self,
        _account_chirho: &AccountIdChirho,
        _epoch_chirho: ShardEpochChirho,
    ) -> MembershipStatusChirho {
        MembershipStatusChirho::NonMemberChirho
    }
}

struct ClosedKindRegistryChirho;

impl KindRegistryViewChirho for ClosedKindRegistryChirho {
    fn resolve_chirho(&self, _policy_ref_chirho: &AssetKindRefChirho) -> KindResolutionChirho {
        KindResolutionChirho::UnknownChirho
    }
}

struct ClosedAuthorityChirho;

impl AuthorityVerifierViewChirho for ClosedAuthorityChirho {
    fn verify_mint_chirho(
        &self,
        _evidence_chirho: &DigestChirho,
        _kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        AuthorityVerdictChirho::UnverifiedChirho
    }

    fn verify_burn_chirho(
        &self,
        _evidence_chirho: &DigestChirho,
        _kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        AuthorityVerdictChirho::UnverifiedChirho
    }
}

struct CompetingCreateSignerChirho<'signer_chirho> {
    inner_chirho: &'signer_chirho dyn LedgerSignerPortChirho,
    competing_path_chirho: PathBuf,
    competing_bytes_chirho: Vec<u8>,
}

impl LedgerSignerPortChirho for CompetingCreateSignerChirho<'_> {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> anyhow::Result<String> {
        fs::write(&self.competing_path_chirho, &self.competing_bytes_chirho)?;
        self.inner_chirho.sign_chirho(signed_content_line_chirho)
    }

    fn key_id_chirho(&self) -> String {
        self.inner_chirho.key_id_chirho()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.inner_chirho
            .verify_chirho(signed_content_line_chirho, sig_chirho)
    }
}

#[test]
fn real_host_ports_create_and_reopen_a_verified_journal_chirho() {
    let root_chirho = temp_root_chirho("journal");
    let storage_root_chirho = root_chirho.join("ledger-namespace-chirho");
    fs::create_dir_all(&storage_root_chirho).unwrap();
    let refs_chirho = provision_signers_chirho(&root_chirho);
    let signers_chirho =
        HostLedgerSignersChirho::load_existing_chirho(&root_chirho, &refs_chirho).unwrap();
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&storage_root_chirho).unwrap();
    let clock_chirho = SystemLedgerClockChirho;
    let membership_chirho = ClosedMembershipChirho;
    let registry_chirho = ClosedKindRegistryChirho;
    let authority_chirho = ClosedAuthorityChirho;
    let ports_chirho = JournalPortsChirho {
        storage_chirho: &storage_chirho,
        signer_chirho: &signers_chirho.journal_chirho,
        clock_chirho: &clock_chirho,
        membership_chirho: &membership_chirho,
        kind_registry_chirho: &registry_chirho,
        authority_chirho: &authority_chirho,
    };
    let path_chirho = StoragePathChirho::new_chirho("journals/host-proof-chirho.jsonl");
    let cluster_chirho = ClusterIdChirho("host-proof-cluster-chirho".to_string());
    let journal_chirho = LedgerJournalChirho::create_chirho(
        ports_chirho,
        path_chirho.clone(),
        cluster_chirho.clone(),
        1,
    )
    .unwrap();
    assert_eq!(journal_chirho.tail_seq_chirho(), 0);
    drop(journal_chirho);
    let reopened_chirho =
        LedgerJournalChirho::open_chirho(ports_chirho, path_chirho, &cluster_chirho).unwrap();
    assert_eq!(reopened_chirho.tail_seq_chirho(), 0);
    assert!(clock_chirho.physical_now_ms_chirho() > 0);
    let _ = fs::remove_dir_all(root_chirho);
}

#[test]
fn concurrent_journal_creator_never_receives_a_genesis_append_chirho() {
    let root_chirho = temp_root_chirho("journal-create-race");
    let storage_root_chirho = root_chirho.join("ledger-namespace-chirho");
    fs::create_dir_all(storage_root_chirho.join("journals")).unwrap();
    let refs_chirho = provision_signers_chirho(&root_chirho);
    let signers_chirho =
        HostLedgerSignersChirho::load_existing_chirho(&root_chirho, &refs_chirho).unwrap();
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&storage_root_chirho).unwrap();
    let clock_chirho = SystemLedgerClockChirho;
    let membership_chirho = ClosedMembershipChirho;
    let registry_chirho = ClosedKindRegistryChirho;
    let authority_chirho = ClosedAuthorityChirho;
    let journal_file_chirho = storage_root_chirho.join("journals/raced-chirho.jsonl");
    let foreign_bytes_chirho = b"foreign-journal-chirho\n".to_vec();
    let signer_chirho = CompetingCreateSignerChirho {
        inner_chirho: &signers_chirho.journal_chirho,
        competing_path_chirho: journal_file_chirho.clone(),
        competing_bytes_chirho: foreign_bytes_chirho.clone(),
    };
    let ports_chirho = JournalPortsChirho {
        storage_chirho: &storage_chirho,
        signer_chirho: &signer_chirho,
        clock_chirho: &clock_chirho,
        membership_chirho: &membership_chirho,
        kind_registry_chirho: &registry_chirho,
        authority_chirho: &authority_chirho,
    };

    let error_chirho = LedgerJournalChirho::create_chirho(
        ports_chirho,
        StoragePathChirho::new_chirho("journals/raced-chirho.jsonl"),
        ClusterIdChirho("raced-cluster-chirho".to_owned()),
        1,
    )
    .err()
    .expect("the concurrent create-only winner must be preserved");
    assert!(matches!(
        error_chirho,
        JournalErrorChirho::ChainChirho { .. }
    ));
    assert_eq!(fs::read(journal_file_chirho).unwrap(), foreign_bytes_chirho);
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn host_adapter_sources_have_no_ambient_or_self_minted_authority_chirho() {
    let production_sources_chirho = [
        include_str!("clock_chirho.rs"),
        include_str!("custody_chirho.rs"),
        include_str!("signer_chirho.rs"),
        // The storage adapter moved to its own crate; this include follows it. Deliberately the
        // SAME single file as before — adding the descriptor source would BROADEN the ambient-
        // authority check, which is an improvement and belongs in its own brick, not a move.
        include_str!("../../host-chirho/cairn-ledger-host-storage-chirho/src/lib.rs"),
    ]
    .join("\n");
    let manifest_chirho = include_str!("../Cargo.toml");
    for forbidden_chirho in [
        "std::env",
        "DATABASE_URL",
        "rusqlite",
        "sqlx",
        "tokio_postgres",
        "SigningKey::generate",
        "OsRng",
    ] {
        assert!(
            !production_sources_chirho.contains(forbidden_chirho)
                && !manifest_chirho.contains(forbidden_chirho),
            "host adapter gained ambient, database, or self-minted authority via {forbidden_chirho}"
        );
    }
    assert_eq!(
        production_sources_chirho
            .matches("resolve_secret_ref_chirho")
            .count(),
        2
    );
}
