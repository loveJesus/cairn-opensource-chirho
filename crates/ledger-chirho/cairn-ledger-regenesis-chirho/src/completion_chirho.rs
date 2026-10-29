// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! H3-B completion: register and publish every configured account-net projection, re-serve the
//! final staged route set, prove conservation, write one canonical no-leak packet, then mint the
//! private completion token required by the atomic publisher.

use crate::bounded_file_chirho::read_bounded_regular_file_chirho;
use crate::error_chirho::{LedgerRegenesisRefusalChirho, LedgerRegenesisResultChirho};
use crate::money_stage_chirho::{
    prepare_money_stage_chirho, LedgerRegenesisH3aRequestChirho, LedgerRegenesisMoneyProofChirho,
    LedgerRegenesisMoneyStageChirho,
};
use crate::publication_verify_chirho::write_staged_publication_manifest_chirho;
use crate::staging_chirho::{
    publish_completed_stage_chirho, CompletedLedgerRegenesisStageChirho,
    PublishedLedgerRegenesisStageChirho,
};
use cairn_config_chirho::config_chirho::validate_ledger_account_owner_chirho;
use cairn_durable_chirho::fsync_dir_chirho;
use cairn_kind_registry_chirho::chain_chirho::{
    load_verified_registry_chirho, KindRegistryPortsChirho,
};
use cairn_ledger_composition_chirho::composition_chirho::JournalConservationSourceChirho;
use cairn_ledger_composition_chirho::LedgerReadCompositionChirho;
use cairn_ledger_conservation_monitor_chirho::{
    run_conservation_monitor_once_chirho, ConservationGreenEvidenceChirho,
};
use cairn_ledger_host_chirho::{
    PinnedKindIssuerVerifierChirho, PlatformPolicyMintAuthorityChirho,
    StaticClusterMembershipChirho, SystemLedgerClockChirho,
};
use cairn_ledger_log_chirho::journal_chirho::JournalPortsChirho;
use cairn_ledger_log_chirho::ports_chirho::StoragePathChirho;
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, ClusterIdChirho, DigestChirho,
    MoneyGroupIdChirho,
};
use cairn_ledger_read_model_chirho::descriptor_chirho::{
    derive_projection_privacy_evidence_ref_chirho, ProjectionCostClassChirho,
    ProjectionDescriptorChirho, ProjectionReadPolicyChirho, ProjectionRebuildLawChirho,
    ProjectionSourceBindingChirho, StalenessContractChirho, VerifiedProjectionSourceChirho,
    PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_read_model_chirho::feeder_chirho::ProjectionSourceChirho;
use cairn_ledger_read_model_chirho::follower_chirho::ProjectionReadOutcomeChirho;
use cairn_ledger_read_model_chirho::registry_chirho::ProjectionRegistryOpChirho;
use cairn_ledger_read_model_chirho::serving_chirho::{
    journal_source_family_id_chirho, FollowerServeOutcomeChirho,
};
use cairn_ledger_read_model_chirho::source_registry_chirho::{
    SourceDeclarationChirho, SourceRegistryOpChirho,
};
use cairn_ledger_read_model_chirho::{
    account_net_projection_fold_ref_chirho, account_net_source_schema_ref_chirho,
    parse_canonical_account_net_projection_view_chirho, projection_descriptor_digest_chirho,
    AccountNetProjectionFoldChirho,
};
use cairn_model_privacy_chirho::PrivacyClassChirho;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

pub const LEDGER_REGENESIS_EVIDENCE_PACKET_SCHEMA_V2_CHIRHO: &str =
    "ledger-regenesis-evidence-packet-v2-chirho";
pub const LEDGER_REGENESIS_EVIDENCE_PACKET_FILE_CHIRHO: &str =
    "ledger-regenesis-evidence-packet-v2-chirho.json";
pub const MAX_LEDGER_REGENESIS_EVIDENCE_PACKET_BYTES_CHIRHO: u64 = 16 * 1024 * 1024;
const LEDGER_REGENESIS_SOURCE_PRIVACY_SCHEMA_V1_CHIRHO: &str =
    "ledger-regenesis-source-privacy-v1-chirho";
const LEDGER_REGENESIS_SOURCE_PRIVACY_DIGEST_DOMAIN_V1_CHIRHO: &str =
    "cairn-ledger-regenesis-source-privacy-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerRegenesisSourcePrivacyEvidenceChirho {
    pub schema_chirho: String,
    pub plan_digest_chirho: String,
    pub family_id_chirho: String,
    pub source_schema_ref_chirho: DigestChirho,
    pub privacy_floor_chirho: PrivacyClassChirho,
    pub privacy_evidence_ref_chirho: DigestChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict_chirho")]
pub enum LedgerRegenesisProjectionVerdictChirho {
    #[serde(rename = "fresh-chirho")]
    FreshChirho { lag_ms_chirho: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerRegenesisProjectionEvidenceChirho {
    pub projection_name_chirho: String,
    pub descriptor_digest_chirho: DigestChirho,
    pub view_digest_chirho: DigestChirho,
    pub source_family_id_chirho: String,
    pub source_seq_chirho: u64,
    pub source_hlc_physical_ms_chirho: u64,
    pub source_hlc_logical_chirho: u32,
    pub signed_prefix_digest_chirho: DigestChirho,
    pub account_chirho: AccountIdChirho,
    pub account_net_chirho: u64,
    pub cost_class_chirho: ProjectionCostClassChirho,
    pub verdict_chirho: LedgerRegenesisProjectionVerdictChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerRegenesisConservationEvidenceChirho {
    pub epoch_chirho: u64,
    pub checkpoint_digest_chirho: DigestChirho,
    pub covered_record_count_chirho: u64,
    pub money_group_kind_scopes_checked_chirho: u64,
    pub domain_kind_rollups_checked_chirho: u64,
    pub global_supplies_checked_chirho: u64,
    pub work_items_checked_chirho: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LedgerRegenesisCaveatChirho {
    #[serde(rename = "signed-per-mint-amount-bound-required-before-production-chirho")]
    SignedPerMintAmountBoundRequiredBeforeProductionChirho,
    #[serde(rename = "request-fastopen-repayment-required-before-client-serving-chirho")]
    RequestFastopenRepaymentRequiredBeforeClientServingChirho,
    #[serde(rename = "root-config-single-operator-custody-chirho")]
    RootConfigSingleOperatorCustodyChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerRegenesisEvidencePacketV2Chirho {
    pub schema_chirho: String,
    pub plan_digest_chirho: String,
    pub money_chirho: LedgerRegenesisMoneyProofChirho,
    pub source_privacy_chirho: LedgerRegenesisSourcePrivacyEvidenceChirho,
    pub projections_chirho: Vec<LedgerRegenesisProjectionEvidenceChirho>,
    pub conservation_chirho: LedgerRegenesisConservationEvidenceChirho,
    pub caveats_chirho: Vec<LedgerRegenesisCaveatChirho>,
}

struct ProvisionedProjectionChirho {
    projection_name_chirho: String,
    head_path_chirho: StoragePathChirho,
    descriptor_digest_chirho: DigestChirho,
}

/// Complete and publish one reviewed H3 plan. The caller supplies no money amount or storage
/// coordinate beyond the already reviewed plan/config files and their required digest.
///
/// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf6-regenesis-boundary-chirho.md`.
pub fn run_ledger_regenesis_chirho(
    request_chirho: LedgerRegenesisH3aRequestChirho<'_>,
) -> LedgerRegenesisResultChirho<PublishedLedgerRegenesisStageChirho> {
    let money_stage_chirho = prepare_money_stage_chirho(request_chirho)?;
    let completed_stage_chirho = complete_money_stage_chirho(money_stage_chirho)?;
    publish_completed_stage_chirho(completed_stage_chirho)
}

/// Add every H3-B proof and write the canonical packet inside the staged operational namespace.
/// The returned token's fields are private, so this function is the only production constructor.
pub fn complete_money_stage_chirho(
    money_stage_chirho: LedgerRegenesisMoneyStageChirho,
) -> LedgerRegenesisResultChirho<CompletedLedgerRegenesisStageChirho> {
    let packet_chirho = build_evidence_packet_chirho(&money_stage_chirho)?;
    let packet_bytes_chirho = canonical_ledger_regenesis_evidence_packet_chirho(&packet_chirho)?;
    let packet_path_chirho = money_stage_chirho
        .monitor_namespace_root_chirho
        .join(LEDGER_REGENESIS_EVIDENCE_PACKET_FILE_CHIRHO);
    write_new_packet_durable_chirho(&packet_path_chirho, &packet_bytes_chirho)?;
    let (parsed_chirho, packet_digest_chirho) =
        load_canonical_ledger_regenesis_evidence_packet_chirho(&packet_path_chirho)?;
    if parsed_chirho != packet_chirho {
        return Err(LedgerRegenesisRefusalChirho::EvidencePacketRefusedChirho);
    }
    let publication_manifest_chirho =
        write_staged_publication_manifest_chirho(&money_stage_chirho, &packet_digest_chirho)?;
    Ok(CompletedLedgerRegenesisStageChirho {
        money_stage_chirho,
        packet_digest_chirho,
        publication_manifest_digest_chirho: publication_manifest_chirho.manifest_digest_chirho,
        publication_proof_chirho: publication_manifest_chirho.publication_proof_chirho,
    })
}

pub fn canonical_ledger_regenesis_evidence_packet_chirho(
    packet_chirho: &LedgerRegenesisEvidencePacketV2Chirho,
) -> LedgerRegenesisResultChirho<Vec<u8>> {
    validate_evidence_packet_chirho(packet_chirho)?;
    serde_json::to_vec(packet_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::EvidencePacketRefusedChirho)
}

pub fn parse_canonical_ledger_regenesis_evidence_packet_chirho(
    bytes_chirho: &[u8],
) -> LedgerRegenesisResultChirho<LedgerRegenesisEvidencePacketV2Chirho> {
    let packet_chirho: LedgerRegenesisEvidencePacketV2Chirho = serde_json::from_slice(bytes_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::EvidencePacketRefusedChirho)?;
    if canonical_ledger_regenesis_evidence_packet_chirho(&packet_chirho)? != bytes_chirho {
        return Err(LedgerRegenesisRefusalChirho::EvidencePacketRefusedChirho);
    }
    Ok(packet_chirho)
}

pub fn ledger_regenesis_evidence_packet_digest_chirho(bytes_chirho: &[u8]) -> String {
    blake3::hash(bytes_chirho).to_hex().to_string()
}

pub fn load_canonical_ledger_regenesis_evidence_packet_chirho(
    path_chirho: &Path,
) -> LedgerRegenesisResultChirho<(LedgerRegenesisEvidencePacketV2Chirho, String)> {
    let bytes_chirho = read_bounded_regular_file_chirho(
        path_chirho,
        MAX_LEDGER_REGENESIS_EVIDENCE_PACKET_BYTES_CHIRHO,
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::EvidencePacketRefusedChirho)?;
    let packet_chirho = parse_canonical_ledger_regenesis_evidence_packet_chirho(&bytes_chirho)?;
    let digest_chirho = ledger_regenesis_evidence_packet_digest_chirho(&bytes_chirho);
    Ok((packet_chirho, digest_chirho))
}

fn build_evidence_packet_chirho(
    money_stage_chirho: &LedgerRegenesisMoneyStageChirho,
) -> LedgerRegenesisResultChirho<LedgerRegenesisEvidencePacketV2Chirho> {
    let plan_chirho = &money_stage_chirho.plan_chirho;
    let cluster_chirho = ClusterIdChirho(plan_chirho.cluster_id_chirho.clone());
    let journal_path_chirho = StoragePathChirho::new_chirho(&plan_chirho.journal_path_chirho);
    let issuer_verify_chirho = PinnedKindIssuerVerifierChirho::from_config_chirho(
        &money_stage_chirho.config_chirho.kind_issuer_chirho,
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::ProjectionCompletionRefusedChirho)?;
    let registry_ports_chirho = KindRegistryPortsChirho {
        storage_chirho: &money_stage_chirho.storage_chirho,
        registry_root_chirho: money_stage_chirho
            .runtime_signers_chirho
            .kind_root_signer_chirho(),
        issuer_verify_chirho: &issuer_verify_chirho,
    };
    let kind_registry_chirho = load_verified_registry_chirho(
        registry_ports_chirho,
        &StoragePathChirho::new_chirho(&plan_chirho.kind_registry_path_chirho),
        &plan_chirho.kind_registry_id_chirho,
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::ProjectionCompletionRefusedChirho)?;
    let authority_chirho = PlatformPolicyMintAuthorityChirho::new_chirho(&kind_registry_chirho);
    let membership_chirho = StaticClusterMembershipChirho::from_config_chirho(
        money_stage_chirho.config_chirho.local_epoch_chirho,
        &money_stage_chirho.config_chirho.members_chirho,
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::ProjectionCompletionRefusedChirho)?;
    let clock_chirho = SystemLedgerClockChirho;
    let journal_ports_chirho = JournalPortsChirho {
        storage_chirho: &money_stage_chirho.storage_chirho,
        signer_chirho: money_stage_chirho
            .runtime_signers_chirho
            .journal_signer_chirho(),
        clock_chirho: &clock_chirho,
        membership_chirho: &membership_chirho,
        kind_registry_chirho: &kind_registry_chirho,
        authority_chirho: &authority_chirho,
    };
    let read_chirho = LedgerReadCompositionChirho {
        journal_ports_chirho,
        config_root_chirho: money_stage_chirho
            .runtime_signers_chirho
            .config_signer_chirho(),
        feeder_root_chirho: money_stage_chirho
            .runtime_signers_chirho
            .feeder_signer_chirho(),
        projection_registry_path_chirho: StoragePathChirho::new_chirho(
            &plan_chirho.projection_registry_path_chirho,
        ),
        projection_registry_id_chirho: plan_chirho.projection_registry_id_chirho.clone(),
        source_registry_path_chirho: StoragePathChirho::new_chirho(
            &plan_chirho.source_registry_path_chirho,
        ),
        source_registry_id_chirho: plan_chirho.source_registry_id_chirho.clone(),
    };

    let family_id_chirho = journal_source_family_id_chirho(&cluster_chirho);
    let source_schema_ref_chirho = account_net_source_schema_ref_chirho();
    let mut source_privacy_chirho = LedgerRegenesisSourcePrivacyEvidenceChirho {
        schema_chirho: LEDGER_REGENESIS_SOURCE_PRIVACY_SCHEMA_V1_CHIRHO.to_owned(),
        plan_digest_chirho: money_stage_chirho.plan_digest_chirho.clone(),
        family_id_chirho: family_id_chirho.clone(),
        source_schema_ref_chirho: source_schema_ref_chirho.clone(),
        privacy_floor_chirho: PrivacyClassChirho::AnalyticalChirho,
        privacy_evidence_ref_chirho: DigestChirho(String::new()),
    };
    source_privacy_chirho.privacy_evidence_ref_chirho =
        source_privacy_evidence_ref_chirho(&source_privacy_chirho)?;
    read_chirho
        .append_source_op_chirho(SourceRegistryOpChirho::RegisterSourceChirho {
            declaration_chirho: SourceDeclarationChirho {
                family_id_chirho: family_id_chirho.clone(),
                schema_ref_chirho: source_schema_ref_chirho.clone(),
                privacy_floor_chirho: PrivacyClassChirho::AnalyticalChirho,
                privacy_evidence_ref_chirho: source_privacy_chirho
                    .privacy_evidence_ref_chirho
                    .clone(),
            },
        })
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::ProjectionCompletionRefusedChirho)?;
    let verified_sources_chirho = vec![VerifiedProjectionSourceChirho {
        binding_chirho: ProjectionSourceBindingChirho {
            family_id_chirho: family_id_chirho.clone(),
            source_schema_ref_chirho,
        },
        privacy_floor_chirho: PrivacyClassChirho::AnalyticalChirho,
        privacy_evidence_ref_chirho: source_privacy_chirho.privacy_evidence_ref_chirho.clone(),
    }];
    let projection_privacy_evidence_chirho = derive_projection_privacy_evidence_ref_chirho(
        &verified_sources_chirho,
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::ProjectionCompletionRefusedChirho)?;

    let mut routes_chirho = plan_chirho.projection_routes_chirho.clone();
    routes_chirho.sort_by(|left_chirho, right_chirho| {
        left_chirho
            .projection_name_chirho
            .cmp(&right_chirho.projection_name_chirho)
    });
    let mut provisioned_chirho = Vec::with_capacity(routes_chirho.len());
    for route_chirho in routes_chirho {
        let descriptor_chirho = ProjectionDescriptorChirho {
            schema_chirho: PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO.to_owned(),
            name_chirho: route_chirho.projection_name_chirho.clone(),
            source_families_chirho: verified_sources_chirho
                .iter()
                .map(|source_chirho| source_chirho.binding_chirho.clone())
                .collect(),
            fold_fn_ref_chirho: account_net_projection_fold_ref_chirho(),
            staleness_contract_chirho: StalenessContractChirho {
                max_owner_hlc_lag_ms_chirho: plan_chirho.monitor_cadence_ms_chirho,
                read_policy_chirho: ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
            },
            cost_class_chirho: ProjectionCostClassChirho::StandingWriteRateChirho,
            privacy_floor_chirho: PrivacyClassChirho::AnalyticalChirho,
            privacy_floor_evidence_ref_chirho: projection_privacy_evidence_chirho.clone(),
            rebuild_law_chirho: ProjectionRebuildLawChirho::DropAndRefoldChirho,
        };
        let descriptor_digest_chirho = projection_descriptor_digest_chirho(&descriptor_chirho)
            .map_err(|_error_chirho| {
                LedgerRegenesisRefusalChirho::ProjectionCompletionRefusedChirho
            })?;
        read_chirho
            .append_projection_op_chirho(ProjectionRegistryOpChirho::RegisterProjectionChirho {
                descriptor_chirho,
            })
            .map_err(|_error_chirho| {
                LedgerRegenesisRefusalChirho::ProjectionCompletionRefusedChirho
            })?;
        provisioned_chirho.push(ProvisionedProjectionChirho {
            projection_name_chirho: route_chirho.projection_name_chirho,
            head_path_chirho: StoragePathChirho::new_chirho(&route_chirho.head_path_chirho),
            descriptor_digest_chirho,
        });
    }

    for projection_chirho in &provisioned_chirho {
        read_chirho
            .feed_and_publish_chirho(
                &projection_chirho.projection_name_chirho,
                &projection_chirho.descriptor_digest_chirho,
                &AccountNetProjectionFoldChirho,
                ProjectionSourceChirho {
                    journal_ports_chirho,
                    journal_path_chirho: &journal_path_chirho,
                    cluster_chirho: &cluster_chirho,
                },
                &projection_chirho.head_path_chirho,
            )
            .map_err(|_error_chirho| {
                LedgerRegenesisRefusalChirho::ProjectionCompletionRefusedChirho
            })?;
    }

    let account_chirho = AccountIdChirho {
        owner_chirho: plan_chirho.initial_owner_chirho.clone(),
        kind_id_chirho: AssetKindIdChirho(plan_chirho.kind_id_chirho.clone()),
    };
    let mut projections_chirho = Vec::with_capacity(provisioned_chirho.len());
    for projection_chirho in &provisioned_chirho {
        let served_chirho = read_chirho
            .load_named_and_serve_with_view_chirho(
                &projection_chirho.projection_name_chirho,
                &projection_chirho.head_path_chirho,
                ProjectionSourceChirho {
                    journal_ports_chirho,
                    journal_path_chirho: &journal_path_chirho,
                    cluster_chirho: &cluster_chirho,
                },
            )
            .map_err(|_error_chirho| {
                LedgerRegenesisRefusalChirho::ProjectionCompletionRefusedChirho
            })?;
        if served_chirho.verified_cost_class_chirho
            != Some(ProjectionCostClassChirho::StandingWriteRateChirho)
        {
            return Err(LedgerRegenesisRefusalChirho::ProjectionCompletionRefusedChirho);
        }
        let view_bytes_chirho = served_chirho
            .view_bytes_chirho
            .as_deref()
            .ok_or(LedgerRegenesisRefusalChirho::ProjectionCompletionRefusedChirho)?;
        let account_view_chirho = parse_canonical_account_net_projection_view_chirho(
            view_bytes_chirho,
        )
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::ProjectionCompletionRefusedChirho)?;
        let account_net_chirho = account_view_chirho
            .rows_chirho
            .iter()
            .find(|row_chirho| row_chirho.account_chirho == account_chirho)
            .map(|row_chirho| row_chirho.account_net_chirho)
            .ok_or(LedgerRegenesisRefusalChirho::ProjectionCompletionRefusedChirho)?;
        if account_net_chirho != plan_chirho.initial_mint_amount_chirho {
            return Err(LedgerRegenesisRefusalChirho::ProjectionCompletionRefusedChirho);
        }
        let (published_view_chirho, lag_ms_chirho) = match served_chirho.outcome_chirho {
            FollowerServeOutcomeChirho::ReadChirho(ProjectionReadOutcomeChirho::FreshChirho {
                view_chirho,
                lag_ms_chirho,
                ..
            }) => (view_chirho, lag_ms_chirho),
            FollowerServeOutcomeChirho::ReadChirho(
                ProjectionReadOutcomeChirho::DegradedChirho { .. }
                | ProjectionReadOutcomeChirho::RefusedChirho(_),
            )
            | FollowerServeOutcomeChirho::GateRefusedChirho(_) => {
                return Err(LedgerRegenesisRefusalChirho::ProjectionCompletionRefusedChirho)
            }
        };
        projections_chirho.push(LedgerRegenesisProjectionEvidenceChirho {
            projection_name_chirho: projection_chirho.projection_name_chirho.clone(),
            descriptor_digest_chirho: projection_chirho.descriptor_digest_chirho.clone(),
            view_digest_chirho: published_view_chirho.state_digest_chirho,
            source_family_id_chirho: published_view_chirho
                .watermark_chirho
                .source_family_id_chirho,
            source_seq_chirho: published_view_chirho.watermark_chirho.source_seq_chirho,
            source_hlc_physical_ms_chirho: published_view_chirho
                .watermark_chirho
                .source_hlc_chirho
                .physical_ms_chirho,
            source_hlc_logical_chirho: published_view_chirho
                .watermark_chirho
                .source_hlc_chirho
                .logical_chirho,
            signed_prefix_digest_chirho: published_view_chirho
                .watermark_chirho
                .signed_prefix_digest_chirho,
            account_chirho: account_chirho.clone(),
            account_net_chirho,
            cost_class_chirho: ProjectionCostClassChirho::StandingWriteRateChirho,
            verdict_chirho: LedgerRegenesisProjectionVerdictChirho::FreshChirho { lag_ms_chirho },
        });
    }

    let conservation_source_chirho = JournalConservationSourceChirho {
        journal_ports_chirho,
        journal_path_chirho,
        cluster_chirho,
        money_group_chirho: MoneyGroupIdChirho(plan_chirho.money_group_id_chirho.clone()),
    };
    let conservation_green_chirho =
        run_conservation_monitor_once_chirho(&conservation_source_chirho)
            .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::ConservationRefusedChirho)?;
    Ok(LedgerRegenesisEvidencePacketV2Chirho {
        schema_chirho: LEDGER_REGENESIS_EVIDENCE_PACKET_SCHEMA_V2_CHIRHO.to_owned(),
        plan_digest_chirho: money_stage_chirho.plan_digest_chirho.clone(),
        money_chirho: money_stage_chirho.proof_chirho().clone(),
        source_privacy_chirho,
        projections_chirho,
        conservation_chirho: conservation_evidence_chirho(&conservation_green_chirho)?,
        caveats_chirho: required_caveats_chirho(),
    })
}

fn source_privacy_evidence_ref_chirho(
    evidence_chirho: &LedgerRegenesisSourcePrivacyEvidenceChirho,
) -> LedgerRegenesisResultChirho<DigestChirho> {
    let mut unsigned_chirho = evidence_chirho.clone();
    unsigned_chirho.privacy_evidence_ref_chirho = DigestChirho(String::new());
    let bytes_chirho = serde_json::to_vec(&unsigned_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::EvidencePacketRefusedChirho)?;
    let mut hasher_chirho =
        blake3::Hasher::new_derive_key(LEDGER_REGENESIS_SOURCE_PRIVACY_DIGEST_DOMAIN_V1_CHIRHO);
    hasher_chirho.update(&bytes_chirho);
    Ok(DigestChirho(hasher_chirho.finalize().to_hex().to_string()))
}

fn conservation_evidence_chirho(
    green_chirho: &ConservationGreenEvidenceChirho,
) -> LedgerRegenesisResultChirho<LedgerRegenesisConservationEvidenceChirho> {
    Ok(LedgerRegenesisConservationEvidenceChirho {
        epoch_chirho: green_chirho.head_chirho.epoch_chirho,
        checkpoint_digest_chirho: green_chirho.head_chirho.checkpoint_digest_chirho.clone(),
        covered_record_count_chirho: green_chirho.head_chirho.covered_record_count_chirho,
        money_group_kind_scopes_checked_chirho: u64::try_from(
            green_chirho.money_group_kind_scopes_checked_chirho,
        )
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::EvidencePacketRefusedChirho)?,
        domain_kind_rollups_checked_chirho: u64::try_from(
            green_chirho.domain_kind_rollups_checked_chirho,
        )
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::EvidencePacketRefusedChirho)?,
        global_supplies_checked_chirho: u64::try_from(green_chirho.global_supplies_checked_chirho)
            .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::EvidencePacketRefusedChirho)?,
        work_items_checked_chirho: u64::try_from(green_chirho.work_items_checked_chirho)
            .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::EvidencePacketRefusedChirho)?,
    })
}

fn required_caveats_chirho() -> Vec<LedgerRegenesisCaveatChirho> {
    vec![
        LedgerRegenesisCaveatChirho::SignedPerMintAmountBoundRequiredBeforeProductionChirho,
        LedgerRegenesisCaveatChirho::RequestFastopenRepaymentRequiredBeforeClientServingChirho,
        LedgerRegenesisCaveatChirho::RootConfigSingleOperatorCustodyChirho,
    ]
}

fn validate_evidence_packet_chirho(
    packet_chirho: &LedgerRegenesisEvidencePacketV2Chirho,
) -> LedgerRegenesisResultChirho<()> {
    let money_chirho = &packet_chirho.money_chirho;
    let activation_chirho = &money_chirho.activation_chirho;
    let canary_chirho = &money_chirho.canary_chirho;
    let source_chirho = &packet_chirho.source_privacy_chirho;
    if packet_chirho.schema_chirho != LEDGER_REGENESIS_EVIDENCE_PACKET_SCHEMA_V2_CHIRHO
        || source_chirho.schema_chirho != LEDGER_REGENESIS_SOURCE_PRIVACY_SCHEMA_V1_CHIRHO
        || packet_chirho.plan_digest_chirho != money_chirho.plan_digest_chirho
        || packet_chirho.plan_digest_chirho != activation_chirho.plan_digest_chirho
        || packet_chirho.plan_digest_chirho != source_chirho.plan_digest_chirho
        || !is_digest_chirho(&packet_chirho.plan_digest_chirho)
        || !is_asset_kind_ref_digest_chirho(&money_chirho.initial_policy_ref_chirho)
        || !is_asset_kind_ref_digest_chirho(&money_chirho.current_policy_ref_chirho)
        || money_chirho.initial_policy_ref_chirho == money_chirho.current_policy_ref_chirho
        || money_chirho.initial_mint_amount_chirho == 0
        || money_chirho.initial_mint_amount_chirho != money_chirho.replayed_supply_chirho
        || !money_chirho.stale_policy_classified_superseded_chirho
        || activation_chirho.append_seq_chirho == 0
        || !is_digest_chirho(&activation_chirho.append_record_digest_chirho.0)
        || activation_chirho.append_hlc_physical_ms_chirho == 0
        || activation_chirho.process_generation_chirho == 0
        || activation_chirho.durable_term_chirho == 0
        || activation_chirho.fence_epoch_chirho == 0
        || canary_chirho.evidence_seq_chirho != 1
        || canary_chirho.window_len_chirho != 1
        || canary_chirho.permit_count_chirho != 1
        || canary_chirho.refusal_count_chirho != 0
        || canary_chirho.append_seq_chirho != activation_chirho.append_seq_chirho
        || canary_chirho.append_record_digest_chirho
            != activation_chirho.append_record_digest_chirho
        || canary_chirho.durable_term_chirho != activation_chirho.durable_term_chirho
        || canary_chirho.fence_epoch_chirho != activation_chirho.fence_epoch_chirho
        || source_chirho.privacy_floor_chirho != PrivacyClassChirho::AnalyticalChirho
        || !is_packet_token_chirho(&source_chirho.family_id_chirho)
        || source_chirho.source_schema_ref_chirho != account_net_source_schema_ref_chirho()
        || !is_digest_chirho(&source_chirho.source_schema_ref_chirho.0)
        || !is_digest_chirho(&source_chirho.privacy_evidence_ref_chirho.0)
        || source_privacy_evidence_ref_chirho(source_chirho)?
            != source_chirho.privacy_evidence_ref_chirho
        || packet_chirho.projections_chirho.is_empty()
        || !packet_chirho
            .projections_chirho
            .windows(2)
            .all(|pair_chirho| {
                pair_chirho[0].projection_name_chirho < pair_chirho[1].projection_name_chirho
            })
        || packet_chirho
            .conservation_chirho
            .covered_record_count_chirho
            == 0
        || packet_chirho.conservation_chirho.epoch_chirho == 0
        || packet_chirho
            .conservation_chirho
            .money_group_kind_scopes_checked_chirho
            == 0
        || packet_chirho
            .conservation_chirho
            .domain_kind_rollups_checked_chirho
            == 0
        || packet_chirho
            .conservation_chirho
            .global_supplies_checked_chirho
            == 0
        || !is_digest_chirho(&packet_chirho.conservation_chirho.checkpoint_digest_chirho.0)
        || packet_chirho.caveats_chirho != required_caveats_chirho()
    {
        return Err(LedgerRegenesisRefusalChirho::EvidencePacketRefusedChirho);
    }
    let expected_account_chirho = &packet_chirho.projections_chirho[0].account_chirho;
    for projection_chirho in &packet_chirho.projections_chirho {
        // Keep packet owners on the shared H3 grammar used by config/plan and aligned with the
        // identity emitter plus the dependency-light credits-demo viewer check.
        if !is_packet_token_chirho(&projection_chirho.projection_name_chirho)
            || validate_ledger_account_owner_chirho(&projection_chirho.account_chirho.owner_chirho)
                .is_err()
            || !is_packet_token_chirho(&projection_chirho.account_chirho.kind_id_chirho.0)
            || projection_chirho.account_chirho != *expected_account_chirho
            || projection_chirho.account_net_chirho != money_chirho.initial_mint_amount_chirho
            || projection_chirho.source_family_id_chirho != source_chirho.family_id_chirho
            || projection_chirho.source_seq_chirho != activation_chirho.append_seq_chirho
            || projection_chirho.source_seq_chirho
                != packet_chirho
                    .conservation_chirho
                    .covered_record_count_chirho
            || projection_chirho.source_hlc_physical_ms_chirho
                != activation_chirho.append_hlc_physical_ms_chirho
            || projection_chirho.source_hlc_logical_chirho
                != activation_chirho.append_hlc_logical_chirho
            || !is_digest_chirho(&projection_chirho.descriptor_digest_chirho.0)
            || !is_digest_chirho(&projection_chirho.view_digest_chirho.0)
            || !is_digest_chirho(&projection_chirho.signed_prefix_digest_chirho.0)
            || !matches!(
                projection_chirho.cost_class_chirho,
                ProjectionCostClassChirho::StandingWriteRateChirho
            )
            || !matches!(
                projection_chirho.verdict_chirho,
                LedgerRegenesisProjectionVerdictChirho::FreshChirho { lag_ms_chirho: 0 }
            )
        {
            return Err(LedgerRegenesisRefusalChirho::EvidencePacketRefusedChirho);
        }
    }
    Ok(())
}

fn write_new_packet_durable_chirho(
    packet_path_chirho: &std::path::Path,
    packet_bytes_chirho: &[u8],
) -> LedgerRegenesisResultChirho<()> {
    if u64::try_from(packet_bytes_chirho.len())
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::EvidencePacketRefusedChirho)?
        > MAX_LEDGER_REGENESIS_EVIDENCE_PACKET_BYTES_CHIRHO
    {
        return Err(LedgerRegenesisRefusalChirho::EvidencePacketRefusedChirho);
    }
    let mut packet_file_chirho = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(packet_path_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::EvidencePacketRefusedChirho)?;
    packet_file_chirho
        .write_all(packet_bytes_chirho)
        .and_then(|()| packet_file_chirho.sync_all())
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::EvidencePacketRefusedChirho)?;
    let parent_chirho = packet_path_chirho
        .parent()
        .ok_or(LedgerRegenesisRefusalChirho::EvidencePacketRefusedChirho)?;
    fsync_dir_chirho(parent_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::EvidencePacketRefusedChirho)
}

fn is_digest_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || matches!(byte_chirho, b'a'..=b'f'))
}

fn is_asset_kind_ref_digest_chirho(value_chirho: &AssetKindRefChirho) -> bool {
    let AssetKindRefChirho(DigestChirho(digest_chirho)) = value_chirho;
    is_digest_chirho(digest_chirho)
}

fn is_packet_token_chirho(value_chirho: &str) -> bool {
    !value_chirho.is_empty()
        && value_chirho.len() <= 128
        && value_chirho.bytes().all(|byte_chirho| {
            byte_chirho.is_ascii_lowercase()
                || byte_chirho.is_ascii_digit()
                || matches!(byte_chirho, b'-' | b'_' | b':' | b'.')
        })
}
