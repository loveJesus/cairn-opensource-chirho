// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use crate::serve_chirho::ledger_host_runtime_chirho::{
    LedgerConservationAlarmPortChirho, LedgerMonitorCadenceWaitPortChirho,
};
use cairn_chirho::effect_chirho::postgres_reversible_chirho::{
    PostgresReversibleExecutionChirho, PostgresReversibleRuntimePortChirho,
};
use cairn_chirho::effect_chirho::projection_read_chirho::{
    PublishedProjectionReadPortChirho, PublishedProjectionReadRequestChirho,
};
use cairn_chirho::model_chirho::{
    CapabilityChirho, DagChirho, HashChirho, NodeDefChirho, PortChirho, RequestContextChirho,
};
use cairn_config_chirho::config_chirho::{
    LedgerHostConfigChirho, LedgerHostIssuerPinConfigChirho, LedgerHostMemberConfigChirho,
    LedgerHostPostgresEffectConfigChirho, LedgerHostPostgresEffectPostureChirho,
    LedgerHostProjectionRouteConfigChirho, LedgerHostSignerRefsConfigChirho,
    LEDGER_HOST_CONFIG_SCHEMA_V1_CHIRHO, LEDGER_HOST_POSTGRES_EFFECT_CONFIG_SCHEMA_V1_CHIRHO,
};
use cairn_kind_registry_chirho::chain_chirho::{
    append_registry_op_chirho, load_verified_registry_chirho, KindRegistryPortsChirho,
};
use cairn_kind_registry_chirho::record_chirho::{
    KindPolicyBodyChirho, KindRegistryOpChirho, MintAuthorityRecordChirho,
};
use cairn_kind_registry_chirho::wire_chirho::derive_policy_ref_chirho;
use cairn_ledger_composition_chirho::{FollowerServeOutcomeChirho, LedgerReadCompositionChirho};
use cairn_ledger_host_chirho::{
    host_ledger_signer_refs_from_config_chirho, FsLedgerStorageChirho,
    HostLedgerConfigCustodyRefusalChirho, HostLedgerSignersChirho, PinnedKindIssuerVerifierChirho,
    PlatformPolicyMintAuthorityChirho, StaticClusterMembershipChirho, SystemLedgerClockChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{
    AppendLegRequestChirho, AppendRequestChirho, JournalPortsChirho, LedgerJournalChirho,
};
use cairn_ledger_log_chirho::ports_chirho::{LedgerSignerPortChirho, StoragePathChirho};
use cairn_ledger_model_chirho::asset_op_chirho::RoundingChirho;
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, ClusterIdChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::{AttributionChirho, LedgerOpChirho, LegDeltaChirho};
use cairn_ledger_model_chirho::LogIdChirho;
use cairn_ledger_read_model_chirho::descriptor_chirho::{
    derive_projection_privacy_evidence_ref_chirho, projection_descriptor_digest_chirho,
    ProjectionCostClassChirho, ProjectionDescriptorChirho, ProjectionReadPolicyChirho,
    ProjectionRebuildLawChirho, ProjectionSourceBindingChirho, StalenessContractChirho,
    PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_read_model_chirho::feeder_chirho::ProjectionSourceChirho;
use cairn_ledger_read_model_chirho::follower_chirho::{
    FollowerReadRefusalChirho, ProjectionReadOutcomeChirho,
};
use cairn_ledger_read_model_chirho::registry_chirho::ProjectionRegistryOpChirho;
use cairn_ledger_read_model_chirho::serving_chirho::journal_source_family_id_chirho;
use cairn_ledger_read_model_chirho::source_registry_chirho::{
    SourceDeclarationChirho, SourceRegistryOpChirho,
};
use cairn_ledger_read_model_chirho::{
    account_net_projection_fold_ref_chirho, account_net_source_schema_ref_chirho,
    parse_canonical_account_net_projection_view_chirho, AccountNetProjectionFoldChirho,
};
use cairn_model_privacy_chirho::PrivacyClassChirho;
use cairn_secret_chirho::secret_chirho::set_secret_chirho;
use cairn_undo_plan_chirho::canonical_chirho::contract_set_digest_chirho;
use cairn_undo_plan_chirho::contract_chirho::{
    canonical_authoring_reversion_contract_set_chirho, POSTGRES_REVERSIBLE_EFFECT_SUBTYPE_CHIRHO,
};
use ed25519_dalek::{Signer, SigningKey};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const STORAGE_NAMESPACE_CHIRHO: &str = "ledger-host-storage-chirho";
const MONITOR_NAMESPACE_CHIRHO: &str = "ledger-monitor-ops-chirho";
const JOURNAL_PATH_CHIRHO: &str = "journals/runtime-chirho.jsonl";
const KIND_REGISTRY_PATH_CHIRHO: &str = "registries/kinds-chirho.jsonl";
const PROJECTION_REGISTRY_PATH_CHIRHO: &str = "registries/projections-chirho.jsonl";
const SOURCE_REGISTRY_PATH_CHIRHO: &str = "registries/sources-chirho.jsonl";
const HEAD_PATH_CHIRHO: &str = "projections/heads/balances-chirho.json";
const PROJECTION_NAME_CHIRHO: &str = "balances-chirho";
static NEXT_LEDGER_HOST_RUNTIME_FIXTURE_ID_CHIRHO: AtomicUsize = AtomicUsize::new(1);

struct LedgerHostRuntimeFixtureChirho {
    root_chirho: PathBuf,
    config_path_chirho: PathBuf,
    config_chirho: LedgerHostConfigChirho,
}

struct FixtureKindIssuerSignerChirho {
    signing_key_chirho: SigningKey,
}

impl FixtureKindIssuerSignerChirho {
    fn new_chirho() -> Self {
        Self {
            signing_key_chirho: SigningKey::from_bytes(&[0x77; 32]),
        }
    }
}

impl LedgerSignerPortChirho for FixtureKindIssuerSignerChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> anyhow::Result<String> {
        Ok(hex_bytes_chirho(
            &self
                .signing_key_chirho
                .sign(signed_content_line_chirho.as_bytes())
                .to_bytes(),
        ))
    }

    fn key_id_chirho(&self) -> String {
        "offline-kind-issuer-redacted-chirho".to_string()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.sign_chirho(signed_content_line_chirho)
            .map(|expected_chirho| expected_chirho == sig_chirho)
            .unwrap_or(false)
    }
}

struct UnusedPostgresRuntimeChirho;

impl PostgresReversibleRuntimePortChirho for UnusedPostgresRuntimeChirho {
    fn execute_chirho(
        &mut self,
        _execution_chirho: PostgresReversibleExecutionChirho<'_>,
    ) -> anyhow::Result<Vec<u8>> {
        panic!("the projection-port keying test must not execute the provider")
    }
}

#[derive(Default)]
struct BlockingDispatchMoneyStateChirho {
    invocation_refs_chirho: Mutex<BTreeSet<String>>,
    payer_debits_chirho: AtomicU64,
    settlement_credits_chirho: AtomicU64,
    terminal_count_chirho: AtomicUsize,
    meter_count_chirho: AtomicUsize,
}

struct BlockingDispatchMoneyRuntimeChirho {
    state_chirho: Arc<BlockingDispatchMoneyStateChirho>,
    expected_payer_chirho: String,
}

impl PostgresReversibleRuntimePortChirho for BlockingDispatchMoneyRuntimeChirho {
    fn execute_chirho(
        &mut self,
        execution_chirho: PostgresReversibleExecutionChirho<'_>,
    ) -> anyhow::Result<Vec<u8>> {
        let nested_runtime_chirho = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        nested_runtime_chirho.block_on(async {});

        let context_chirho = execution_chirho.request_context_chirho();
        assert_eq!(
            context_chirho.user_principal_chirho,
            self.expected_payer_chirho
        );
        let resolved_price_chirho = cairn_chirho::effect_pricing_chirho::resolve_price_chirho(
            execution_chirho.root_chirho(),
            &context_chirho.app_chirho,
            POSTGRES_REVERSIBLE_EFFECT_SUBTYPE_CHIRHO,
        )?;
        assert_eq!(resolved_price_chirho.price_chirho, 10);
        assert_eq!(
            context_chirho.price_book_chirho.as_ref(),
            Some(&resolved_price_chirho.price_book_chirho)
        );

        let first_terminal_chirho = self
            .state_chirho
            .invocation_refs_chirho
            .lock()
            .expect("the blocking-dispatch invocation set must remain available")
            .insert(execution_chirho.invocation_ref_chirho().0.clone());
        if first_terminal_chirho {
            let amount_chirho = u64::try_from(resolved_price_chirho.price_chirho)?;
            self.state_chirho
                .payer_debits_chirho
                .fetch_add(amount_chirho, Ordering::SeqCst);
            self.state_chirho
                .settlement_credits_chirho
                .fetch_add(amount_chirho, Ordering::SeqCst);
            self.state_chirho
                .terminal_count_chirho
                .fetch_add(1, Ordering::SeqCst);
            self.state_chirho
                .meter_count_chirho
                .fetch_add(1, Ordering::SeqCst);
        }
        Ok(b"descriptor-d-committed-terminal-chirho".to_vec())
    }
}

struct PanickingBlockingDispatchRuntimeChirho;

impl PostgresReversibleRuntimePortChirho for PanickingBlockingDispatchRuntimeChirho {
    fn execute_chirho(
        &mut self,
        _execution_chirho: PostgresReversibleExecutionChirho<'_>,
    ) -> anyhow::Result<Vec<u8>> {
        panic!("injected blocking Descriptor-D provider panic")
    }
}

impl LedgerHostRuntimeFixtureChirho {
    fn new_chirho() -> Self {
        let fixture_label_chirho = format!(
            "ledger-host-runtime-{}-chirho",
            NEXT_LEDGER_HOST_RUNTIME_FIXTURE_ID_CHIRHO.fetch_add(1, Ordering::Relaxed)
        );
        let root_chirho = temp_root_chirho(&fixture_label_chirho);
        fs::create_dir_all(root_chirho.join(STORAGE_NAMESPACE_CHIRHO)).unwrap();
        fs::create_dir_all(root_chirho.join(MONITOR_NAMESPACE_CHIRHO)).unwrap();
        let config_path_chirho = root_chirho.join("cairn-host-chirho.toml");
        fs::write(&config_path_chirho, b"ledger-host-config-chirho").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&config_path_chirho, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let signer_names_chirho = [
            "journal-secret-chirho",
            "config-secret-chirho",
            "feeder-secret-chirho",
            "kind-root-secret-chirho",
            "effect-intent-secret-chirho",
            "effect-terminal-secret-chirho",
        ];
        for (index_chirho, signer_name_chirho) in signer_names_chirho.iter().enumerate() {
            set_secret_chirho(
                &root_chirho,
                signer_name_chirho,
                &[u8::try_from(index_chirho + 1).unwrap(); 32],
            )
            .unwrap();
        }
        set_secret_chirho(
            &root_chirho,
            cairn_chirho::effect_chirho::postgres_reversible_chirho::ADAPTER_EVIDENCE_SECRET_NAME_CHIRHO,
            &[0x71; 32],
        )
        .unwrap();
        let issuer_signing_chirho = SigningKey::from_bytes(&[0x77; 32]);
        let config_chirho = LedgerHostConfigChirho {
            schema_chirho: LEDGER_HOST_CONFIG_SCHEMA_V1_CHIRHO.to_string(),
            storage_namespace_chirho: STORAGE_NAMESPACE_CHIRHO.to_string(),
            monitor_evidence_namespace_chirho: MONITOR_NAMESPACE_CHIRHO.to_string(),
            monitor_evidence_path_chirho: "cycles/conservation-chirho.jsonl".to_string(),
            money_group_id_chirho: "money-group-local-chirho".to_string(),
            cluster_id_chirho: "cluster-local-chirho".to_string(),
            journal_path_chirho: JOURNAL_PATH_CHIRHO.to_string(),
            local_epoch_chirho: 1,
            members_chirho: vec![LedgerHostMemberConfigChirho {
                owner_chirho: "platform-owner-chirho".to_string(),
                kind_id_chirho: "credits-chirho".to_string(),
            }],
            kind_registry_path_chirho: KIND_REGISTRY_PATH_CHIRHO.to_string(),
            kind_registry_id_chirho: "kind-registry-local-chirho".to_string(),
            kind_issuer_chirho: LedgerHostIssuerPinConfigChirho {
                principal_chirho: "offline-kind-issuer-chirho".to_string(),
                verifying_key_hex_chirho: hex_bytes_chirho(
                    issuer_signing_chirho.verifying_key().as_bytes(),
                ),
            },
            activation_authority_chirho: None,
            projection_registry_path_chirho: PROJECTION_REGISTRY_PATH_CHIRHO.to_string(),
            projection_registry_id_chirho: "projection-registry-local-chirho".to_string(),
            source_registry_path_chirho: SOURCE_REGISTRY_PATH_CHIRHO.to_string(),
            source_registry_id_chirho: "source-registry-local-chirho".to_string(),
            projection_routes_chirho: vec![LedgerHostProjectionRouteConfigChirho {
                projection_name_chirho: PROJECTION_NAME_CHIRHO.to_string(),
                head_path_chirho: HEAD_PATH_CHIRHO.to_string(),
            }],
            signer_secrets_chirho: LedgerHostSignerRefsConfigChirho {
                journal_chirho: signer_names_chirho[0].to_string(),
                config_chirho: signer_names_chirho[1].to_string(),
                feeder_chirho: signer_names_chirho[2].to_string(),
                kind_root_chirho: signer_names_chirho[3].to_string(),
                effect_intent_chirho: signer_names_chirho[4].to_string(),
                effect_terminal_chirho: signer_names_chirho[5].to_string(),
            },
            held_verifier_pins_chirho: None,
            migration_destination_authority_chirho: None,
            monitor_cadence_ms_chirho: 5_000,
            postgres_effect_chirho: None,
            control_plane_chirho: None,
            test_kind_chirho: None,
            adopt_migrated_root_chirho: false,
        };
        config_chirho.validate_chirho().unwrap();
        provision_published_projection_chirho(&root_chirho, &config_chirho);
        Self {
            root_chirho,
            config_path_chirho,
            config_chirho,
        }
    }
}

fn hex_bytes_chirho(bytes_chirho: &[u8]) -> String {
    bytes_chirho
        .iter()
        .map(|byte_chirho| format!("{byte_chirho:02x}"))
        .collect()
}

fn provision_published_projection_chirho(
    root_chirho: &Path,
    config_chirho: &LedgerHostConfigChirho,
) {
    let storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&root_chirho.join(STORAGE_NAMESPACE_CHIRHO))
            .unwrap();
    let signer_refs_chirho =
        host_ledger_signer_refs_from_config_chirho(&config_chirho.signer_secrets_chirho).unwrap();
    let signers_chirho =
        HostLedgerSignersChirho::load_existing_chirho(root_chirho, &signer_refs_chirho).unwrap();
    let membership_chirho = StaticClusterMembershipChirho::from_config_chirho(
        config_chirho.local_epoch_chirho,
        &config_chirho.members_chirho,
    )
    .unwrap();
    let issuer_verify_chirho =
        PinnedKindIssuerVerifierChirho::from_config_chirho(&config_chirho.kind_issuer_chirho)
            .unwrap();
    let kind_registry_chirho = load_verified_registry_chirho(
        KindRegistryPortsChirho {
            storage_chirho: &storage_chirho,
            registry_root_chirho: signers_chirho.kind_root_signer_chirho(),
            issuer_verify_chirho: &issuer_verify_chirho,
        },
        &StoragePathChirho::new_chirho(KIND_REGISTRY_PATH_CHIRHO),
        &config_chirho.kind_registry_id_chirho,
    )
    .unwrap();
    let authority_chirho = PlatformPolicyMintAuthorityChirho::new_chirho(&kind_registry_chirho);
    let clock_chirho = SystemLedgerClockChirho;
    let journal_ports_chirho = JournalPortsChirho {
        storage_chirho: &storage_chirho,
        signer_chirho: signers_chirho.journal_signer_chirho(),
        clock_chirho: &clock_chirho,
        membership_chirho: &membership_chirho,
        kind_registry_chirho: &kind_registry_chirho,
        authority_chirho: &authority_chirho,
    };
    drop(
        LedgerJournalChirho::create_chirho(
            journal_ports_chirho,
            StoragePathChirho::new_chirho(JOURNAL_PATH_CHIRHO),
            ClusterIdChirho(config_chirho.cluster_id_chirho.clone()),
            config_chirho.local_epoch_chirho,
        )
        .unwrap(),
    );

    let read_chirho = LedgerReadCompositionChirho {
        journal_ports_chirho,
        config_root_chirho: signers_chirho.config_signer_chirho(),
        feeder_root_chirho: signers_chirho.feeder_signer_chirho(),
        projection_registry_path_chirho: StoragePathChirho::new_chirho(
            PROJECTION_REGISTRY_PATH_CHIRHO,
        ),
        projection_registry_id_chirho: config_chirho.projection_registry_id_chirho.clone(),
        source_registry_path_chirho: StoragePathChirho::new_chirho(SOURCE_REGISTRY_PATH_CHIRHO),
        source_registry_id_chirho: config_chirho.source_registry_id_chirho.clone(),
    };
    let cluster_chirho = ClusterIdChirho(config_chirho.cluster_id_chirho.clone());
    let source_family_chirho = journal_source_family_id_chirho(&cluster_chirho);
    let source_schema_chirho = account_net_source_schema_ref_chirho();
    let source_privacy_evidence_chirho = DigestChirho("cc".repeat(32));
    read_chirho
        .append_source_op_chirho(SourceRegistryOpChirho::RegisterSourceChirho {
            declaration_chirho: SourceDeclarationChirho {
                family_id_chirho: source_family_chirho.clone(),
                schema_ref_chirho: source_schema_chirho.clone(),
                privacy_floor_chirho: PrivacyClassChirho::AnalyticalChirho,
                privacy_evidence_ref_chirho: source_privacy_evidence_chirho.clone(),
            },
        })
        .unwrap();
    let sources_chirho = vec![
        cairn_ledger_read_model_chirho::descriptor_chirho::VerifiedProjectionSourceChirho {
            binding_chirho: ProjectionSourceBindingChirho {
                family_id_chirho: source_family_chirho,
                source_schema_ref_chirho: source_schema_chirho,
            },
            privacy_floor_chirho: PrivacyClassChirho::AnalyticalChirho,
            privacy_evidence_ref_chirho: source_privacy_evidence_chirho,
        },
    ];
    let descriptor_chirho = ProjectionDescriptorChirho {
        schema_chirho: PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO.to_string(),
        name_chirho: PROJECTION_NAME_CHIRHO.to_string(),
        source_families_chirho: sources_chirho
            .iter()
            .map(|source_chirho| source_chirho.binding_chirho.clone())
            .collect(),
        fold_fn_ref_chirho: account_net_projection_fold_ref_chirho(),
        staleness_contract_chirho: StalenessContractChirho {
            max_owner_hlc_lag_ms_chirho: 5_000,
            read_policy_chirho: ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
        },
        cost_class_chirho: ProjectionCostClassChirho::StandingWriteRateChirho,
        privacy_floor_chirho: PrivacyClassChirho::AnalyticalChirho,
        privacy_floor_evidence_ref_chirho: derive_projection_privacy_evidence_ref_chirho(
            &sources_chirho,
        )
        .unwrap(),
        rebuild_law_chirho: ProjectionRebuildLawChirho::DropAndRefoldChirho,
    };
    let descriptor_digest_chirho = projection_descriptor_digest_chirho(&descriptor_chirho).unwrap();
    read_chirho
        .append_projection_op_chirho(ProjectionRegistryOpChirho::RegisterProjectionChirho {
            descriptor_chirho,
        })
        .unwrap();
    let journal_path_chirho = StoragePathChirho::new_chirho(JOURNAL_PATH_CHIRHO);
    read_chirho
        .feed_and_publish_chirho(
            PROJECTION_NAME_CHIRHO,
            &descriptor_digest_chirho,
            &AccountNetProjectionFoldChirho,
            ProjectionSourceChirho {
                journal_ports_chirho,
                journal_path_chirho: &journal_path_chirho,
                cluster_chirho: &cluster_chirho,
            },
            &StoragePathChirho::new_chirho(HEAD_PATH_CHIRHO),
        )
        .unwrap();
}

fn advance_journal_without_refeed_chirho(fixture_chirho: &LedgerHostRuntimeFixtureChirho) {
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(
        &fixture_chirho.root_chirho.join(STORAGE_NAMESPACE_CHIRHO),
    )
    .unwrap();
    let signer_refs_chirho = host_ledger_signer_refs_from_config_chirho(
        &fixture_chirho.config_chirho.signer_secrets_chirho,
    )
    .unwrap();
    let signers_chirho = HostLedgerSignersChirho::load_existing_chirho(
        &fixture_chirho.root_chirho,
        &signer_refs_chirho,
    )
    .unwrap();
    let membership_chirho = StaticClusterMembershipChirho::from_config_chirho(
        fixture_chirho.config_chirho.local_epoch_chirho,
        &fixture_chirho.config_chirho.members_chirho,
    )
    .unwrap();
    let issuer_verify_chirho = PinnedKindIssuerVerifierChirho::from_config_chirho(
        &fixture_chirho.config_chirho.kind_issuer_chirho,
    )
    .unwrap();
    let registry_ports_chirho = KindRegistryPortsChirho {
        storage_chirho: &storage_chirho,
        registry_root_chirho: signers_chirho.kind_root_signer_chirho(),
        issuer_verify_chirho: &issuer_verify_chirho,
    };
    let policy_chirho = KindPolicyBodyChirho {
        unit_chirho: "credit-minor-chirho".to_string(),
        precision_chirho: 0,
        mint_authority_chirho: MintAuthorityRecordChirho::PlatformPolicyChirho {
            max_supply_chirho: Some(1_000),
        },
        rounding_chirho: RoundingChirho::NearestTiesToEvenChirho,
        shard_attachment_chirho: "shard-local-chirho".to_string(),
        settlement_owner_chirho: Some("settlement-owner-chirho".to_string()),
        idempotency_window_chirho: None,
    };
    let policy_ref_chirho = derive_policy_ref_chirho(&policy_chirho).unwrap();
    append_registry_op_chirho(
        registry_ports_chirho,
        &FixtureKindIssuerSignerChirho::new_chirho(),
        &StoragePathChirho::new_chirho(KIND_REGISTRY_PATH_CHIRHO),
        &fixture_chirho.config_chirho.kind_registry_id_chirho,
        &fixture_chirho
            .config_chirho
            .kind_issuer_chirho
            .principal_chirho,
        KindRegistryOpChirho::RegisterKindChirho {
            kind_id_chirho: AssetKindIdChirho("credits-chirho".to_string()),
            policy_chirho,
        },
    )
    .unwrap();
    let kind_registry_chirho = load_verified_registry_chirho(
        registry_ports_chirho,
        &StoragePathChirho::new_chirho(KIND_REGISTRY_PATH_CHIRHO),
        &fixture_chirho.config_chirho.kind_registry_id_chirho,
    )
    .unwrap();
    let authority_chirho = PlatformPolicyMintAuthorityChirho::new_chirho(&kind_registry_chirho);
    let clock_chirho = SystemLedgerClockChirho;
    let journal_ports_chirho = JournalPortsChirho {
        storage_chirho: &storage_chirho,
        signer_chirho: signers_chirho.journal_signer_chirho(),
        clock_chirho: &clock_chirho,
        membership_chirho: &membership_chirho,
        kind_registry_chirho: &kind_registry_chirho,
        authority_chirho: &authority_chirho,
    };
    let mut journal_chirho = LedgerJournalChirho::open_chirho(
        journal_ports_chirho,
        StoragePathChirho::new_chirho(JOURNAL_PATH_CHIRHO),
        &ClusterIdChirho(fixture_chirho.config_chirho.cluster_id_chirho.clone()),
    )
    .unwrap();
    for record_index_chirho in 0..2 {
        journal_chirho
            .append_chirho(AppendRequestChirho {
                op_chirho: LedgerOpChirho::MintChirho {
                    authority_evidence_chirho: policy_ref_chirho.0.clone(),
                },
                legs_chirho: vec![AppendLegRequestChirho {
                    account_chirho: LogIdChirho::new_chirho(
                        "platform-owner-chirho",
                        "credits-chirho",
                    ),
                    kind_policy_ref_chirho: policy_ref_chirho.clone(),
                    delta_chirho: LegDeltaChirho::CreditChirho,
                    amount_chirho: 1,
                    counterpart_chirho: None,
                }],
                idempotency_key_chirho: format!("effect-cut-behind-{record_index_chirho}-chirho"),
                provenance_chirho: None,
                attribution_chirho: AttributionChirho::PlatformChirho,
            })
            .unwrap();
    }
}

fn request_context_chirho() -> RequestContextChirho {
    RequestContextChirho {
        user_principal_chirho: "reader-user-chirho".to_string(),
        app_chirho: "credits-demo-chirho".to_string(),
        owner_principal_chirho: "reader-owner-chirho".to_string(),
        client_id_chirho: "reader-client-chirho".to_string(),
        token_hash_chirho: "reader-token-hash-chirho".to_string(),
        price_book_chirho: None,
        billing_policy_chirho: None,
        key_limit_chirho: None,
    }
}

/// The blocking-dispatch app, its context, and the payer's raw scoped bearer (for arms on the HTTP road).
pub(super) fn blocking_dispatch_fixture_with_bearer_chirho(
    root_chirho: &Path,
) -> (HashChirho, RequestContextChirho, String) {
    let owner_chirho = cairn_chirho::identity_chirho::register_identity_chirho(
        root_chirho,
        cairn_chirho::identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let payer_chirho = cairn_chirho::identity_chirho::register_identity_with_credential_chirho(
        root_chirho,
        cairn_chirho::identity_chirho::PrincipalKindChirho::UserChirho,
        "blocking-dispatch-secret-chirho",
    )
    .unwrap();
    let contract_set_chirho =
        contract_set_digest_chirho(&canonical_authoring_reversion_contract_set_chirho()).unwrap();
    let bytes_schema_chirho = HashChirho("bytes".to_string());
    let node_chirho = NodeDefChirho {
        name_chirho: "served-blocking-descriptor-d-chirho".to_string(),
        impl_wasm_chirho: HashChirho("builtin:descriptor-d-postgres-chirho".to_string()),
        entry_chirho: "descriptor_d_postgres_chirho".to_string(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: bytes_schema_chirho.clone(),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: bytes_schema_chirho,
        }],
        capabilities_chirho: vec![CapabilityChirho::PaidEffectChirho {
            effect_chirho: POSTGRES_REVERSIBLE_EFFECT_SUBTYPE_CHIRHO.to_string(),
            caller_chirho: "served-blocking-dispatch-chirho".to_string(),
        }],
        fuel_limit_chirho: 0,
        effect_contract_set_chirho: Some(contract_set_chirho),
        ..NodeDefChirho::default()
    };
    let node_hash_chirho =
        cairn_chirho::store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap();
    let dag_hash_chirho = cairn_chirho::store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![node_hash_chirho],
            edges_chirho: Vec::new(),
        },
    )
    .unwrap();
    cairn_chirho::app_chirho::deploy_app_chirho(
        root_chirho,
        "blocking-dispatch-app-chirho",
        dag_hash_chirho.clone(),
        &owner_chirho,
    )
    .unwrap();
    let client_chirho = cairn_chirho::oauth_chirho::register_client_chirho(
        root_chirho,
        "blocking-dispatch-app-chirho",
        &owner_chirho,
    )
    .unwrap();
    let token_chirho = cairn_chirho::oauth_chirho::issue_scoped_token_chirho(
        root_chirho,
        &payer_chirho.principal_chirho,
        "blocking-dispatch-secret-chirho",
        &client_chirho.client_id_chirho,
        vec!["invoke_chirho".to_string()],
    )
    .unwrap();
    let (price_book_chirho, _, _) = cairn_chirho::effect_pricing_chirho::set_price_book_chirho(
        root_chirho,
        "blocking-dispatch-app-chirho",
        &owner_chirho,
        None,
        BTreeMap::from([(POSTGRES_REVERSIBLE_EFFECT_SUBTYPE_CHIRHO.to_string(), 10)]),
        0,
    )
    .unwrap();
    (
        dag_hash_chirho,
        RequestContextChirho {
            user_principal_chirho: payer_chirho.principal_chirho,
            app_chirho: "blocking-dispatch-app-chirho".to_string(),
            owner_principal_chirho: owner_chirho,
            client_id_chirho: client_chirho.client_id_chirho,
            token_hash_chirho: token_chirho.record_chirho.token_hash_chirho,
            price_book_chirho: Some(price_book_chirho),
            billing_policy_chirho: None,
            key_limit_chirho: None,
        },
        token_chirho.token_chirho,
    )
}

#[derive(Default)]
struct RecordingLifecycleAlarmChirho {
    red_pages_chirho: AtomicUsize,
    refused_pages_chirho: AtomicUsize,
    evidence_write_pages_chirho: AtomicUsize,
    evidence_write_page_chirho: tokio::sync::Notify,
}

impl RecordingLifecycleAlarmChirho {
    async fn wait_for_evidence_write_page_chirho(&self) {
        loop {
            let page_chirho = self.evidence_write_page_chirho.notified();
            if self.evidence_write_pages_chirho.load(Ordering::SeqCst) > 0 {
                return;
            }
            page_chirho.await;
        }
    }
}

impl LedgerConservationAlarmPortChirho for RecordingLifecycleAlarmChirho {
    fn page_red_chirho(&self) {
        self.red_pages_chirho.fetch_add(1, Ordering::SeqCst);
    }

    fn page_refused_chirho(&self) {
        self.refused_pages_chirho.fetch_add(1, Ordering::SeqCst);
    }

    fn page_evidence_write_chirho(&self) {
        self.evidence_write_pages_chirho
            .fetch_add(1, Ordering::SeqCst);
        self.evidence_write_page_chirho.notify_waiters();
    }
}

struct ControlledLedgerMonitorWaitChirho {
    cadence_sender_chirho: tokio::sync::mpsc::UnboundedSender<Duration>,
    release_chirho: tokio::sync::Semaphore,
    active_waits_chirho: AtomicUsize,
    active_waits_changed_chirho: tokio::sync::Notify,
}

impl ControlledLedgerMonitorWaitChirho {
    fn new_chirho() -> (Arc<Self>, tokio::sync::mpsc::UnboundedReceiver<Duration>) {
        let (cadence_sender_chirho, cadence_receiver_chirho) =
            tokio::sync::mpsc::unbounded_channel();
        (
            Arc::new(Self {
                cadence_sender_chirho,
                release_chirho: tokio::sync::Semaphore::new(0),
                active_waits_chirho: AtomicUsize::new(0),
                active_waits_changed_chirho: tokio::sync::Notify::new(),
            }),
            cadence_receiver_chirho,
        )
    }

    fn release_one_chirho(&self) {
        self.release_chirho.add_permits(1);
    }

    async fn wait_until_inactive_chirho(&self) {
        loop {
            let changed_chirho = self.active_waits_changed_chirho.notified();
            if self.active_waits_chirho.load(Ordering::SeqCst) == 0 {
                return;
            }
            changed_chirho.await;
        }
    }
}

struct ActiveLedgerMonitorWaitGuardChirho<'a> {
    wait_chirho: &'a ControlledLedgerMonitorWaitChirho,
}

impl Drop for ActiveLedgerMonitorWaitGuardChirho<'_> {
    fn drop(&mut self) {
        self.wait_chirho
            .active_waits_chirho
            .fetch_sub(1, Ordering::SeqCst);
        self.wait_chirho
            .active_waits_changed_chirho
            .notify_waiters();
    }
}

impl LedgerMonitorCadenceWaitPortChirho for ControlledLedgerMonitorWaitChirho {
    fn wait_chirho(
        &self,
        cadence_chirho: Duration,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            self.active_waits_chirho.fetch_add(1, Ordering::SeqCst);
            let _guard_chirho = ActiveLedgerMonitorWaitGuardChirho { wait_chirho: self };
            self.cadence_sender_chirho
                .send(cadence_chirho)
                .expect("the controlled cadence receiver must remain live");
            if let Ok(permit_chirho) = self.release_chirho.acquire().await {
                permit_chirho.forget();
            }
        })
    }
}

fn monitor_evidence_rows_chirho(root_chirho: &Path) -> Vec<LedgerConservationCycleRowChirho> {
    fs::read(
        root_chirho
            .join(MONITOR_NAMESPACE_CHIRHO)
            .join("cycles/conservation-chirho.jsonl"),
    )
    .unwrap()
    .split(|byte_chirho| *byte_chirho == b'\n')
    .filter(|line_chirho| !line_chirho.is_empty())
    .map(|line_chirho| parse_ledger_conservation_cycle_row_chirho(line_chirho).unwrap())
    .collect()
}

#[test]
fn configured_ledger_host_preflight_and_reads_are_storage_read_only_chirho() {
    let fixture_chirho = LedgerHostRuntimeFixtureChirho::new_chirho();
    let before_open_chirho = runtime_tree_snapshot_chirho(&fixture_chirho.root_chirho);
    let port_chirho = LedgerHostProjectionReadPortChirho::open_existing_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
        &fixture_chirho.config_chirho,
    )
    .unwrap();
    assert_eq!(
        runtime_tree_snapshot_chirho(&fixture_chirho.root_chirho),
        before_open_chirho
    );
    assert_eq!(port_chirho.monitor_cadence_ms_chirho(), 5_000);
    assert_eq!(
        port_chirho.monitor_evidence_path_chirho(),
        "cycles/conservation-chirho.jsonl"
    );
    assert_eq!(
        port_chirho.money_group_chirho().0,
        "money-group-local-chirho"
    );

    let context_chirho = request_context_chirho();
    let read_chirho = port_chirho
        .read_published_projection_chirho(&PublishedProjectionReadRequestChirho {
            projection_name_chirho: PROJECTION_NAME_CHIRHO,
            requested_limit_chirho: 5,
            request_context_chirho: &context_chirho,
        })
        .unwrap();
    let view_chirho = parse_canonical_account_net_projection_view_chirho(
        read_chirho.view_bytes_chirho.as_deref().unwrap(),
    )
    .unwrap();
    assert!(view_chirho.rows_chirho.is_empty());
    assert!(matches!(
        read_chirho.outcome_chirho,
        FollowerServeOutcomeChirho::ReadChirho(ProjectionReadOutcomeChirho::FreshChirho { .. })
    ));

    for hostile_name_chirho in ["unknown-chirho", "../../ledger-monitor-ops-chirho"] {
        let error_chirho = port_chirho
            .read_published_projection_chirho(&PublishedProjectionReadRequestChirho {
                projection_name_chirho: hostile_name_chirho,
                requested_limit_chirho: 5,
                request_context_chirho: &context_chirho,
            })
            .unwrap_err();
        assert_eq!(
            error_chirho.downcast_ref::<LedgerHostRuntimeRefusalChirho>(),
            Some(&LedgerHostRuntimeRefusalChirho::ProjectionNotConfiguredChirho)
        );
        assert!(!error_chirho.to_string().contains(hostile_name_chirho));
    }
    assert_eq!(
        runtime_tree_snapshot_chirho(&fixture_chirho.root_chirho),
        before_open_chirho,
        "preflight and served reads must not write ledger or monitor evidence namespaces"
    );
    let _ = fs::remove_dir_all(fixture_chirho.root_chirho);
}

#[test]
fn effect_provider_presence_keys_the_serve_projection_freshness_posture_chirho() {
    let fixture_chirho = LedgerHostRuntimeFixtureChirho::new_chirho();
    advance_journal_without_refeed_chirho(&fixture_chirho);
    let host_chirho = Arc::new(
        LedgerHostProjectionReadPortChirho::open_existing_chirho(
            &fixture_chirho.root_chirho,
            &fixture_chirho.config_path_chirho,
            &fixture_chirho.config_chirho,
        )
        .unwrap(),
    );
    let provider_chirho = SharedLedgerHostPostgresEffectRuntimeChirho::from_runtime_for_test_chirho(
        Box::new(UnusedPostgresRuntimeChirho),
    );
    let projection_only_chirho =
        projection_read_port_for_effect_posture_chirho(host_chirho.clone(), None);
    let effect_composed_chirho =
        projection_read_port_for_effect_posture_chirho(host_chirho, Some(&provider_chirho));
    let context_chirho = request_context_chirho();
    let request_chirho = PublishedProjectionReadRequestChirho {
        projection_name_chirho: PROJECTION_NAME_CHIRHO,
        requested_limit_chirho: 5,
        request_context_chirho: &context_chirho,
    };

    let projection_only_read_chirho = projection_only_chirho
        .read_published_projection_chirho(&request_chirho)
        .unwrap();
    assert!(matches!(
        projection_only_read_chirho.outcome_chirho,
        FollowerServeOutcomeChirho::ReadChirho(ProjectionReadOutcomeChirho::FreshChirho { .. })
    ));
    assert!(projection_only_read_chirho.view_bytes_chirho.is_some());

    let effect_composed_read_chirho = effect_composed_chirho
        .read_published_projection_chirho(&request_chirho)
        .unwrap();
    assert_eq!(effect_composed_read_chirho.view_bytes_chirho, None);
    assert_eq!(
        effect_composed_read_chirho.outcome_chirho,
        FollowerServeOutcomeChirho::ReadChirho(ProjectionReadOutcomeChirho::RefusedChirho(
            FollowerReadRefusalChirho::EffectCutBehindChirho,
        ))
    );
    let _ = fs::remove_dir_all(fixture_chirho.root_chirho);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provider_composed_served_write_runs_off_worker_and_meters_once_chirho() {
    let root_chirho = temp_root_chirho("served-blocking-write");
    let (dag_chirho, context_chirho, _) =
        blocking_dispatch_fixture_with_bearer_chirho(&root_chirho);
    let money_state_chirho = Arc::new(BlockingDispatchMoneyStateChirho::default());
    let provider_chirho = SharedLedgerHostPostgresEffectRuntimeChirho::from_runtime_for_test_chirho(
        Box::new(BlockingDispatchMoneyRuntimeChirho {
            state_chirho: money_state_chirho.clone(),
            expected_payer_chirho: context_chirho.user_principal_chirho.clone(),
        }),
    );
    let runtime_chirho = ServedRuntimeRootChirho::with_effect_runtime_chirho(
        &root_chirho,
        None,
        Some(provider_chirho),
        None,
    );

    let first_chirho = runtime_chirho
        .run_dag_with_intent_for_served_request_and_caller_key_chirho(
            dag_chirho.clone(),
            b"served-blocking-request-chirho".to_vec(),
            Some(context_chirho.clone()),
            None,
            None,
        )
        .await
        .unwrap();
    let replay_chirho = runtime_chirho
        .run_dag_with_intent_for_served_request_and_caller_key_chirho(
            dag_chirho,
            b"served-blocking-request-chirho".to_vec(),
            Some(context_chirho),
            None,
            None,
        )
        .await
        .unwrap();

    assert_eq!(first_chirho, b"descriptor-d-committed-terminal-chirho");
    assert_eq!(replay_chirho, first_chirho);
    assert_eq!(
        money_state_chirho
            .payer_debits_chirho
            .load(Ordering::SeqCst),
        10
    );
    assert_eq!(
        money_state_chirho
            .settlement_credits_chirho
            .load(Ordering::SeqCst),
        10
    );
    assert_eq!(
        money_state_chirho
            .terminal_count_chirho
            .load(Ordering::SeqCst),
        1
    );
    assert_eq!(
        money_state_chirho.meter_count_chirho.load(Ordering::SeqCst),
        1
    );
    let _ = fs::remove_dir_all(root_chirho);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocking_provider_panic_returns_typed_refusal_without_money_chirho() {
    let root_chirho = temp_root_chirho("served-blocking-panic");
    let (dag_chirho, context_chirho, _) =
        blocking_dispatch_fixture_with_bearer_chirho(&root_chirho);
    let provider_chirho = SharedLedgerHostPostgresEffectRuntimeChirho::from_runtime_for_test_chirho(
        Box::new(PanickingBlockingDispatchRuntimeChirho),
    );
    let runtime_chirho = ServedRuntimeRootChirho::with_effect_runtime_chirho(
        &root_chirho,
        None,
        Some(provider_chirho),
        None,
    );

    let error_chirho = runtime_chirho
        .run_dag_with_intent_for_served_request_and_caller_key_chirho(
            dag_chirho,
            b"served-blocking-panic-request-chirho".to_vec(),
            Some(context_chirho),
            None,
            None,
        )
        .await
        .unwrap_err();

    assert_eq!(
        error_chirho.downcast_ref::<LedgerHostPostgresEffectRefusalChirho>(),
        Some(&LedgerHostPostgresEffectRefusalChirho::BlockingDispatchUnavailableChirho)
    );
    assert!(!root_chirho.join("effects-chirho").exists());
    let _ = fs::remove_dir_all(root_chirho);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unfinished_forward_provider_resume_runs_off_worker_exactly_once_chirho() {
    const CHILD_ROOT_ENV_CHIRHO: &str = "CAIRN_BLOCKING_RESUME_ROOT_CHIRHO";
    const CHILD_DAG_ENV_CHIRHO: &str = "CAIRN_BLOCKING_RESUME_DAG_CHIRHO";
    const CHILD_CONTEXT_ENV_CHIRHO: &str = "CAIRN_BLOCKING_RESUME_CONTEXT_CHIRHO";
    if let Ok(root_chirho) = std::env::var(CHILD_ROOT_ENV_CHIRHO) {
        let dag_chirho = HashChirho(
            std::env::var(CHILD_DAG_ENV_CHIRHO)
                .expect("the crash child must receive the prepared DAG hash"),
        );
        let context_chirho: RequestContextChirho = serde_json::from_str(
            &std::env::var(CHILD_CONTEXT_ENV_CHIRHO)
                .expect("the crash child must receive the verified request context"),
        )
        .unwrap();
        let provider_chirho =
            SharedLedgerHostPostgresEffectRuntimeChirho::from_runtime_for_test_chirho(Box::new(
                PanickingBlockingDispatchRuntimeChirho,
            ));
        let runtime_chirho = ServedRuntimeRootChirho::with_effect_runtime_chirho(
            Path::new(&root_chirho),
            None,
            Some(provider_chirho),
            None,
        );
        let error_chirho = runtime_chirho
            .run_dag_with_intent_for_served_request_and_caller_key_chirho(
                dag_chirho,
                b"startup-blocking-resume-request-chirho".to_vec(),
                Some(context_chirho),
                None,
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(
            error_chirho.downcast_ref::<LedgerHostPostgresEffectRefusalChirho>(),
            Some(&LedgerHostPostgresEffectRefusalChirho::BlockingDispatchUnavailableChirho)
        );
        return;
    }

    let root_chirho = temp_root_chirho("startup-blocking-resume");
    let (dag_chirho, context_chirho, _) =
        blocking_dispatch_fixture_with_bearer_chirho(&root_chirho);
    let child_status_chirho = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("unfinished_forward_provider_resume_runs_off_worker_exactly_once_chirho")
        .arg("--nocapture")
        .env(CHILD_ROOT_ENV_CHIRHO, &root_chirho)
        .env(CHILD_DAG_ENV_CHIRHO, &dag_chirho.0)
        .env(
            CHILD_CONTEXT_ENV_CHIRHO,
            serde_json::to_string(&context_chirho).unwrap(),
        )
        .status()
        .unwrap();
    assert!(
        child_status_chirho.success(),
        "the crash child must leave one recoverable Running intent"
    );

    let money_state_chirho = Arc::new(BlockingDispatchMoneyStateChirho::default());
    let resume_provider_chirho =
        SharedLedgerHostPostgresEffectRuntimeChirho::from_runtime_for_test_chirho(Box::new(
            BlockingDispatchMoneyRuntimeChirho {
                state_chirho: money_state_chirho.clone(),
                expected_payer_chirho: context_chirho.user_principal_chirho,
            },
        ));
    let first_resume_chirho = resume_unfinished_run_intents_for_served_effect_runtime_chirho(
        root_chirho.clone(),
        None,
        resume_provider_chirho.clone(),
    )
    .await
    .unwrap();
    assert_eq!(first_resume_chirho.unfinished_chirho, 1);
    assert_eq!(first_resume_chirho.resumed_chirho, 1);
    assert_eq!(first_resume_chirho.failed_chirho, 0);
    assert_eq!(
        money_state_chirho
            .payer_debits_chirho
            .load(Ordering::SeqCst),
        10
    );
    assert_eq!(
        money_state_chirho
            .settlement_credits_chirho
            .load(Ordering::SeqCst),
        10
    );
    assert_eq!(
        money_state_chirho
            .terminal_count_chirho
            .load(Ordering::SeqCst),
        1
    );
    assert_eq!(
        money_state_chirho.meter_count_chirho.load(Ordering::SeqCst),
        1
    );

    let replay_resume_chirho = resume_unfinished_run_intents_for_served_effect_runtime_chirho(
        root_chirho.clone(),
        None,
        resume_provider_chirho,
    )
    .await
    .unwrap();
    assert_eq!(replay_resume_chirho.unfinished_chirho, 0);
    assert_eq!(replay_resume_chirho.resumed_chirho, 0);
    assert_eq!(
        money_state_chirho
            .terminal_count_chirho
            .load(Ordering::SeqCst),
        1
    );
    assert_eq!(
        money_state_chirho.meter_count_chirho.load(Ordering::SeqCst),
        1
    );
    let _ = fs::remove_dir_all(root_chirho);
}

#[test]
fn local_phase_b_refuses_missing_current_billing_policy_before_connection_or_writes_chirho() {
    let fixture_chirho = LedgerHostRuntimeFixtureChirho::new_chirho();
    let host_chirho = Arc::new(
        LedgerHostProjectionReadPortChirho::open_existing_chirho(
            &fixture_chirho.root_chirho,
            &fixture_chirho.config_path_chirho,
            &fixture_chirho.config_chirho,
        )
        .unwrap(),
    );
    let before_open_chirho = runtime_tree_snapshot_chirho(&fixture_chirho.root_chirho);
    let postgres_config_chirho = LedgerHostPostgresEffectConfigChirho {
        schema_chirho: LEDGER_HOST_POSTGRES_EFFECT_CONFIG_SCHEMA_V1_CHIRHO.to_string(),
        posture_chirho: LedgerHostPostgresEffectPostureChirho::LocalPhaseBChirho,
        connection_secret_chirho: "missing-postgres-connection-chirho".to_string(),
        billing_kind_chirho: "credits-chirho".to_string(),
    };
    let mut ledger_config_chirho = fixture_chirho.config_chirho.clone();
    ledger_config_chirho.postgres_effect_chirho = Some(postgres_config_chirho);

    let error_chirho = open_shared_ledger_host_postgres_effect_runtime_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
        host_chirho,
        &ledger_config_chirho,
    )
    .err()
    .expect("a missing current settlement policy must refuse before connecting");

    assert_eq!(
        error_chirho.downcast_ref::<LedgerHostPostgresEffectRefusalChirho>(),
        Some(&LedgerHostPostgresEffectRefusalChirho::BillingKindUnavailableChirho)
    );
    assert_eq!(
        runtime_tree_snapshot_chirho(&fixture_chirho.root_chirho),
        before_open_chirho,
        "effect-lane startup refusal must not write provider, ledger, feed, or evidence state"
    );
    let _ = fs::remove_dir_all(fixture_chirho.root_chirho);
}

#[test]
fn configured_head_for_another_projection_refuses_before_runtime_start_chirho() {
    let fixture_chirho = LedgerHostRuntimeFixtureChirho::new_chirho();
    let before_open_chirho = runtime_tree_snapshot_chirho(&fixture_chirho.root_chirho);
    let mut mismatched_config_chirho = fixture_chirho.config_chirho.clone();
    mismatched_config_chirho.projection_routes_chirho[0].projection_name_chirho =
        "foreign-projection-chirho".to_string();
    let error_chirho = LedgerHostProjectionReadPortChirho::open_existing_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
        &mismatched_config_chirho,
    )
    .err()
    .expect("a foreign signed head must not wear the configured route");
    assert_eq!(
        error_chirho.downcast_ref::<LedgerHostRuntimeRefusalChirho>(),
        Some(&LedgerHostRuntimeRefusalChirho::ProjectionPreflightUnavailableChirho)
    );
    assert_eq!(
        runtime_tree_snapshot_chirho(&fixture_chirho.root_chirho),
        before_open_chirho
    );
    let _ = fs::remove_dir_all(fixture_chirho.root_chirho);
}

#[test]
fn conservation_cycle_reloads_the_full_read_only_source_each_time_chirho() {
    let fixture_chirho = LedgerHostRuntimeFixtureChirho::new_chirho();
    let port_chirho = LedgerHostProjectionReadPortChirho::open_existing_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
        &fixture_chirho.config_chirho,
    )
    .unwrap();
    let ledger_root_chirho = fixture_chirho.root_chirho.join(STORAGE_NAMESPACE_CHIRHO);
    let before_cycle_chirho = runtime_tree_snapshot_chirho(&ledger_root_chirho);

    let first_chirho = port_chirho.run_conservation_cycle_once_chirho().unwrap();
    assert!(matches!(
        first_chirho.outcome_chirho,
        LedgerConservationCycleOutcomeChirho::GreenChirho { .. }
    ));
    assert_eq!(
        runtime_tree_snapshot_chirho(&ledger_root_chirho),
        before_cycle_chirho
    );

    let journal_file_chirho = ledger_root_chirho.join(JOURNAL_PATH_CHIRHO);
    let mut writer_chirho = fs::OpenOptions::new()
        .append(true)
        .open(&journal_file_chirho)
        .unwrap();
    writer_chirho
        .write_all(br#"{"schema_chirho":"torn-ledger-record-chirho"#)
        .unwrap();
    writer_chirho.sync_all().unwrap();
    let torn_bytes_chirho = fs::read(&journal_file_chirho).unwrap();

    let second_chirho = port_chirho.run_conservation_cycle_once_chirho().unwrap();
    assert_eq!(
        second_chirho.outcome_chirho,
        LedgerConservationCycleOutcomeChirho::RefusedChirho {
            reason_chirho: LedgerConservationRefusalCodeChirho::JournalRecoveryRequiredChirho,
        }
    );
    assert_eq!(fs::read(&journal_file_chirho).unwrap(), torn_bytes_chirho);
    let rows_chirho = monitor_evidence_rows_chirho(&fixture_chirho.root_chirho);
    assert_eq!(rows_chirho, vec![first_chirho, second_chirho]);
    let _ = fs::remove_dir_all(fixture_chirho.root_chirho);
}

#[test]
fn served_lifecycle_waits_runs_continues_and_aborts_the_monitor_chirho() {
    let fixture_chirho = LedgerHostRuntimeFixtureChirho::new_chirho();
    let host_chirho = Arc::new(
        LedgerHostProjectionReadPortChirho::open_existing_chirho(
            &fixture_chirho.root_chirho,
            &fixture_chirho.config_path_chirho,
            &fixture_chirho.config_chirho,
        )
        .unwrap(),
    );
    let (wait_chirho, mut cadence_receiver_chirho) =
        ControlledLedgerMonitorWaitChirho::new_chirho();
    let alarm_chirho = Arc::new(RecordingLifecycleAlarmChirho::default());
    let port_chirho = unused_local_port_chirho();
    let address_chirho = format!("127.0.0.1:{port_chirho}");
    let root_chirho = fixture_chirho.root_chirho.clone();
    let root_for_server_chirho = root_chirho.clone();
    let wait_for_server_chirho = wait_chirho.clone();
    let alarm_for_server_chirho = alarm_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();

    runtime_chirho.block_on(async move {
        let mut server_chirho = tokio::spawn(async move {
            serve_with_configured_ledger_host_and_monitor_ports_until_chirho(
                &root_for_server_chirho,
                port_chirho,
                ConfiguredLedgerHostServeOptionsChirho {
                    inflight_limit_chirho: 8,
                    auth_tokens_chirho: ServeAuthTokensChirho::default(),
                    domain_routing_enabled_chirho: false,
                    served_request_limits_chirho: ServedRequestAbuseLimitsChirho::default(),
                    ledger_host_chirho: Some(host_chirho),
                    postgres_effect_chirho: None,
                    monitor_wait_chirho: wait_for_server_chirho,
                    monitor_alarm_chirho: alarm_for_server_chirho,
                    write_dispatch_chirho: None,
                    local_read_authority_chirho: None,
                    write_destination_slot_chirho: None,
                    startup_posture_chirho:
                        ConfiguredServeStartupPostureChirho::RecoverRunIntentsAndMonitorChirho,
                },
                None,
            )
            .await
        });

        assert_eq!(
            cadence_receiver_chirho.recv().await,
            Some(Duration::from_millis(5_000))
        );
        let evidence_file_chirho = root_chirho
            .join(MONITOR_NAMESPACE_CHIRHO)
            .join("cycles/conservation-chirho.jsonl");
        assert!(!evidence_file_chirho.exists(), "the first cycle must wait");
        let health_response_chirho =
            http_request_for_smoke_chirho(&address_chirho, "GET", "/healthz-chirho", &[], b"");
        assert_eq!(health_response_chirho.status_chirho, 200);
        assert_eq!(health_response_chirho.body_chirho.as_slice(), b"ok\n");

        wait_chirho.release_one_chirho();
        assert_eq!(
            cadence_receiver_chirho.recv().await,
            Some(Duration::from_millis(5_000))
        );
        let rows_chirho = monitor_evidence_rows_chirho(&root_chirho);
        assert_eq!(rows_chirho.len(), 1);
        assert!(matches!(
            rows_chirho[0].outcome_chirho,
            LedgerConservationCycleOutcomeChirho::GreenChirho { .. }
        ));
        assert_eq!(alarm_chirho.red_pages_chirho.load(Ordering::SeqCst), 0);
        assert_eq!(alarm_chirho.refused_pages_chirho.load(Ordering::SeqCst), 0);

        fs::remove_file(&evidence_file_chirho).unwrap();
        fs::create_dir(&evidence_file_chirho).unwrap();
        wait_chirho.release_one_chirho();
        alarm_chirho.wait_for_evidence_write_page_chirho().await;
        assert_eq!(
            alarm_chirho
                .evidence_write_pages_chirho
                .load(Ordering::SeqCst),
            1,
            "a missing cycle row must be represented by the fixed page"
        );
        tokio::select! {
            cadence_chirho = cadence_receiver_chirho.recv() => assert_eq!(
                cadence_chirho,
                Some(Duration::from_millis(5_000)),
                "the monitor must continue to the next configured cadence"
            ),
            server_result_chirho = &mut server_chirho => panic!(
                "monitor evidence failure propagated into serve: {server_result_chirho:?}"
            ),
        }
        assert_eq!(
            http_request_for_smoke_chirho(&address_chirho, "GET", "/healthz-chirho", &[], b"")
                .status_chirho,
            200,
            "monitor evidence failure must not halt serving"
        );

        server_chirho.abort();
        assert!(server_chirho.await.unwrap_err().is_cancelled());
        wait_chirho.wait_until_inactive_chirho().await;
        assert_eq!(wait_chirho.active_waits_chirho.load(Ordering::SeqCst), 0);
    });
    let _ = fs::remove_dir_all(fixture_chirho.root_chirho);
}

#[cfg(unix)]
#[test]
fn configured_ledger_host_open_enforces_config_custody_chirho() {
    use std::os::unix::fs::PermissionsExt;

    let fixture_chirho = LedgerHostRuntimeFixtureChirho::new_chirho();
    fs::set_permissions(
        &fixture_chirho.config_path_chirho,
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let before_open_chirho = runtime_tree_snapshot_chirho(&fixture_chirho.root_chirho);
    let error_chirho = LedgerHostProjectionReadPortChirho::open_existing_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
        &fixture_chirho.config_chirho,
    )
    .err()
    .expect("the real host open must retain the config-custody gate");
    assert_eq!(
        error_chirho.downcast_ref::<HostLedgerConfigCustodyRefusalChirho>(),
        Some(&HostLedgerConfigCustodyRefusalChirho::ConfigModeTooBroadChirho)
    );
    assert_eq!(
        runtime_tree_snapshot_chirho(&fixture_chirho.root_chirho),
        before_open_chirho
    );
    let _ = fs::remove_dir_all(fixture_chirho.root_chirho);
}

#[tokio::test]
async fn configured_runtime_obeys_shared_process_stop_chirho() {
    let root_chirho = temp_root_chirho("shared-process-stop");
    let stop_chirho = Arc::new(std::sync::atomic::AtomicBool::new(true));
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        serve_with_configured_ledger_host_chirho(
            &root_chirho,
            0,
            1,
            ServeAuthTokensChirho::new_chirho(String::new(), String::new()),
            false,
            ServedRequestAbuseLimitsChirho::default(),
            ConfiguredLedgerHostRuntimePortsChirho::uncomposed_chirho()
                .with_process_stop_chirho(stop_chirho),
        ),
    )
    .await
    .expect("the shared stop completes the configured server promptly")
    .expect("the configured server shuts down cleanly");
    let _ = fs::remove_dir_all(root_chirho);
}

#[test]
fn relay_only_follower_startup_neither_recovers_intents_nor_changes_root_bytes_chirho() {
    let root_chirho = temp_root_chirho("relay-only-startup");
    let malformed_intents_chirho = b"planted-unfinished-run-intent-chirho\n";
    fs::create_dir_all(&root_chirho).unwrap();
    fs::write(
        root_chirho.join("run-intents-chirho.jsonl"),
        malformed_intents_chirho,
    )
    .unwrap();
    let before_chirho = runtime_tree_snapshot_chirho(&root_chirho);

    resume_projection_run_intents_for_startup_posture_chirho(
        &root_chirho,
        None,
        ConfiguredServeStartupPostureChirho::RelayOnlyFollowerChirho,
    )
    .expect("relay-only follower must not enter durable run-intent recovery");

    assert_eq!(
        runtime_tree_snapshot_chirho(&root_chirho),
        before_chirho,
        "relay-only startup must not create a lock, append a row, or change planted state"
    );

    let normal_root_chirho = temp_root_chirho("normal-startup-positive-control");
    fs::create_dir_all(&normal_root_chirho).unwrap();
    fs::write(
        normal_root_chirho.join("run-intents-chirho.jsonl"),
        malformed_intents_chirho,
    )
    .unwrap();
    assert!(
        resume_projection_run_intents_for_startup_posture_chirho(
            &normal_root_chirho,
            None,
            ConfiguredServeStartupPostureChirho::RecoverRunIntentsAndMonitorChirho,
        )
        .is_err(),
        "positive control: the normal posture must still enter and validate startup recovery"
    );

    let _ = fs::remove_dir_all(root_chirho);
    let _ = fs::remove_dir_all(normal_root_chirho);
}

#[test]
fn relay_only_follower_http_rejects_control_plane_before_handler_or_root_write_chirho() {
    let root_chirho = temp_root_chirho("relay-only-http-boundary");
    fs::create_dir_all(&root_chirho).unwrap();
    fs::write(
        root_chirho.join("planted-follower-state-chirho"),
        b"must-remain-byte-identical-chirho",
    )
    .unwrap();
    let before_chirho = runtime_tree_snapshot_chirho(&root_chirho);
    let router_chirho = runtime_router_for_root_with_effect_runtime_after_resume_chirho(
        &root_chirho,
        RuntimeAppStateOptionsChirho {
            inflight_limit_chirho: 8,
            auth_tokens_chirho: ServeAuthTokensChirho::new_chirho(
                "relay-only-publish-token-chirho".to_string(),
                String::new(),
            ),
            domain_routing_enabled_chirho: false,
            served_request_limits_chirho: ServedRequestAbuseLimitsChirho::default(),
            projection_read_chirho: None,
            postgres_effect_chirho: None,
            llm_served_chirho: None,
            write_dispatch_chirho: None,
            local_read_authority_chirho: None,
            write_destination_slot_chirho: None,
        },
        true,
    )
    .expect("assemble the production relay-only router layer");
    assert_eq!(
        runtime_tree_snapshot_chirho(&root_chirho),
        before_chirho,
        "relay-only router construction must leave planted follower bytes unchanged"
    );
    let root_for_request_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();

    runtime_chirho.block_on(async move {
        let listener_chirho = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address_chirho = listener_chirho.local_addr().unwrap().to_string();
        let server_chirho = tokio::spawn(async move {
            axum::serve(
                listener_chirho,
                router_chirho.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
        });

        let response_chirho = http_request_for_smoke_chirho(
            &address_chirho,
            "POST",
            "/publish-chirho",
            &[(
                "authorization",
                "Bearer relay-only-publish-token-chirho",
            )],
            br#"{"must_not_reach_handler_chirho":true}"#,
        );
        assert_eq!(response_chirho.status_chirho, 503);
        let body_chirho = http_body_text_chirho(&response_chirho);
        assert!(
            body_chirho.contains("RelayMutationFamilyUnconvertedChirho"),
            "{body_chirho}"
        );
        assert!(
            !body_chirho.contains("unauthorized") && !body_chirho.contains("manifest"),
            "the outer relay-only refusal must precede control-plane auth and parsing: {body_chirho}"
        );
        assert_eq!(
            runtime_tree_snapshot_chirho(&root_for_request_chirho),
            before_chirho,
            "an unconverted control-plane request must leave planted follower bytes unchanged"
        );

        server_chirho.abort();
        assert!(server_chirho.await.unwrap_err().is_cancelled());
    });
    let _ = fs::remove_dir_all(root_chirho);
}

#[tokio::test]
async fn preexisting_process_stop_refuses_before_unfinished_effect_recovery_chirho() {
    let root_chirho = temp_root_chirho("stop-before-effect-recovery");
    let malformed_intents_chirho = b"not-a-run-intent-record-chirho\n";
    fs::create_dir_all(&root_chirho).unwrap();
    fs::write(
        root_chirho.join("run-intents-chirho.jsonl"),
        malformed_intents_chirho,
    )
    .unwrap();
    let stop_chirho = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let provider_chirho = SharedLedgerHostPostgresEffectRuntimeChirho::from_runtime_for_test_chirho(
        Box::new(UnusedPostgresRuntimeChirho),
    );

    serve_with_options_until_chirho(
        &root_chirho,
        0,
        ServeOptionsChirho {
            inflight_limit_chirho: 1,
            auth_tokens_chirho: ServeAuthTokensChirho::default(),
            announce_chirho: false,
            domain_routing_enabled_chirho: false,
            served_request_limits_chirho: ServedRequestAbuseLimitsChirho::default(),
            projection_read_chirho: None,
            postgres_effect_chirho: Some(provider_chirho),
            llm_served_chirho: None,
            ledger_monitor_chirho: None,
            write_dispatch_chirho: None,
            local_read_authority_chirho: None,
            write_destination_slot_chirho: None,
            startup_posture_chirho:
                ConfiguredServeStartupPostureChirho::RecoverRunIntentsAndMonitorChirho,
        },
        Some(stop_chirho),
    )
    .await
    .expect("a preexisting stop exits before malformed unfinished-effect recovery");
    assert_eq!(
        fs::read(root_chirho.join("run-intents-chirho.jsonl")).unwrap(),
        malformed_intents_chirho
    );
    let _ = fs::remove_dir_all(root_chirho);
}
