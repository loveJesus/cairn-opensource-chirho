// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! H3-A's real money flow: register R1, mint through the reviewed activation door, supersede with
//! R2, prove structural read-only replay, then classify R1 as superseded without a second append.

use crate::bounded_file_chirho::read_bounded_regular_file_chirho;
use crate::error_chirho::{LedgerRegenesisRefusalChirho, LedgerRegenesisResultChirho};
use crate::issuer_chirho::{OfflineKindIssuerSignerChirho, OfflineLedgerActivationSignerChirho};
use crate::plan_chirho::{load_verified_plan_chirho, LedgerRegenesisPlanV1Chirho};
use crate::staging_chirho::begin_staging_chirho;
use cairn_config_chirho::config_chirho::LedgerHostConfigChirho;
use cairn_kind_registry_chirho::chain_chirho::{
    append_registry_op_chirho, load_verified_registry_chirho, KindRegistryPortsChirho,
};
use cairn_kind_registry_chirho::record_chirho::KindRegistryOpChirho;
use cairn_kind_registry_chirho::wire_chirho::derive_policy_ref_chirho;
use cairn_ledger_host_chirho::{
    activate_reviewed_h3_chirho, canonical_resident_ledger_activation_authorization_chirho,
    host_ledger_signer_refs_from_config_chirho,
    parse_canonical_resident_ledger_activation_authorization_chirho,
    resident_ledger_activation_statement_chirho,
    verify_resident_ledger_activation_authorization_chirho, FsLedgerStorageChirho,
    HostLedgerSignersChirho, LedgerSignerRoleChirho, PinnedKindIssuerVerifierChirho,
    PinnedLedgerActivationVerifierChirho, PlatformPolicyMintAuthorityChirho,
    ResidentLedgerActivationAuthorizationChirho, ResidentLedgerActivationInputChirho,
    ResidentLedgerActivationReceiptChirho, ResidentLedgerActivationStatementInputChirho,
    ResidentLedgerClockChirho, ResidentLedgerLocalPortsChirho, ResidentLedgerMintIntentChirho,
    StaticClusterMembershipChirho, MAX_RESIDENT_LEDGER_ACTIVATION_AUTHORIZATION_BYTES_CHIRHO,
};
use cairn_ledger_log_chirho::admission_chirho::{
    KindRegistryViewChirho, KindResolutionChirho, MembershipStatusChirho, MembershipViewChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{JournalPortsChirho, LedgerJournalChirho};
use cairn_ledger_log_chirho::ports_chirho::StoragePathChirho;
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, ClusterIdChirho, DigestChirho,
};
use cairn_signer_chirho::signer_chirho::existing_keypair_pubkey_hex_chirho;
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_elector_chirho::shadow_canary_activation_anchor_chirho::ShadowCanaryActivationAnchorInputChirho;
use cairn_writer_elector_chirho::shadow_canary_chirho::{
    observe_shadow_canary_chirho, ShadowCanaryAppendCutChirho, ShadowCanaryEvidenceStoreChirho,
    SHADOW_CANARY_EVIDENCE_DIR_CHIRHO,
};
use cairn_writer_elector_chirho::shadow_canary_generation_chirho::ShadowCanaryGenerationStoreChirho;
use cairn_writer_head_chirho::writer_head_chirho::consistency_group_for_root_chirho;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const H3_SINGLE_NODE_WARMUP_TICKS_CHIRHO: u8 = 10;
const H3_ELECTION_STATE_DIR_CHIRHO: &str = "writer-election-chirho";

fn activation_observation_wall_ms_chirho() -> LedgerRegenesisResultChirho<u64> {
    let elapsed_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::MoneyProvisionRefusedChirho)?;
    u64::try_from(elapsed_chirho.as_millis())
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::MoneyProvisionRefusedChirho)
}

pub struct LedgerRegenesisH3aRequestChirho<'request_chirho> {
    pub selected_root_chirho: &'request_chirho Path,
    pub config_path_chirho: &'request_chirho Path,
    pub plan_path_chirho: &'request_chirho Path,
    pub expected_plan_digest_chirho: &'request_chirho str,
    pub issuer_secret_name_chirho: &'request_chirho str,
    pub activation_authorization_path_chirho: &'request_chirho Path,
    pub expected_activation_authorization_digest_chirho: &'request_chirho str,
}

/// Read-only authoring request. It may read the separately-custodied activation key, but cannot
/// create a staging namespace, register policy, append a journal record, or publish a ledger.
pub struct LedgerRegenesisActivationAuthorRequestChirho<'request_chirho> {
    pub selected_root_chirho: &'request_chirho Path,
    pub config_path_chirho: &'request_chirho Path,
    pub plan_path_chirho: &'request_chirho Path,
    pub expected_plan_digest_chirho: &'request_chirho str,
    pub issuer_secret_name_chirho: &'request_chirho str,
    pub activation_secret_name_chirho: &'request_chirho str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerRegenesisActivationArtifactChirho {
    pub authorization_chirho: ResidentLedgerActivationAuthorizationChirho,
    pub canonical_bytes_chirho: Vec<u8>,
    pub authorization_digest_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerRegenesisMoneyProofChirho {
    pub plan_digest_chirho: String,
    pub initial_policy_ref_chirho: AssetKindRefChirho,
    pub current_policy_ref_chirho: AssetKindRefChirho,
    pub initial_mint_amount_chirho: u64,
    pub replayed_supply_chirho: u64,
    pub stale_policy_classified_superseded_chirho: bool,
    pub activation_chirho: LedgerRegenesisActivationProofChirho,
    pub canary_chirho: LedgerRegenesisCanaryProofChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerRegenesisActivationProofChirho {
    pub plan_digest_chirho: String,
    pub append_seq_chirho: u64,
    pub append_record_digest_chirho: DigestChirho,
    pub append_hlc_physical_ms_chirho: u64,
    pub append_hlc_logical_chirho: u32,
    pub process_generation_chirho: u64,
    pub durable_term_chirho: u64,
    pub fence_epoch_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerRegenesisCanaryProofChirho {
    pub evidence_seq_chirho: u64,
    pub window_len_chirho: u64,
    pub permit_count_chirho: u64,
    pub refusal_count_chirho: u64,
    pub append_seq_chirho: u64,
    pub append_record_digest_chirho: DigestChirho,
    pub durable_term_chirho: u64,
    pub fence_epoch_chirho: u64,
}

/// A non-live, money-provisioned stage. Paths and signer authority remain private; H3-B consumes
/// this value inside the operator crate, adds projections/evidence, and alone creates the private
/// completion token required by `publish_completed_stage_chirho`.
pub struct LedgerRegenesisMoneyStageChirho {
    pub(crate) selected_root_chirho: PathBuf,
    pub(crate) final_parent_chirho: PathBuf,
    pub(crate) staging_parent_chirho: PathBuf,
    pub(crate) monitor_namespace_root_chirho: PathBuf,
    pub(crate) storage_chirho: FsLedgerStorageChirho,
    pub(crate) config_chirho: LedgerHostConfigChirho,
    pub(crate) runtime_signers_chirho: HostLedgerSignersChirho,
    pub(crate) plan_chirho: LedgerRegenesisPlanV1Chirho,
    pub(crate) plan_digest_chirho: String,
    pub(crate) activation_receipt_chirho: ResidentLedgerActivationReceiptChirho,
    pub(crate) canary_evidence_digest_chirho: String,
    proof_chirho: LedgerRegenesisMoneyProofChirho,
}

struct ProvisionedMoneyChirho {
    proof_chirho: LedgerRegenesisMoneyProofChirho,
    activation_receipt_chirho: ResidentLedgerActivationReceiptChirho,
    canary_evidence_digest_chirho: String,
}

struct RecordedActivationCanaryChirho {
    proof_chirho: LedgerRegenesisCanaryProofChirho,
    evidence_digest_chirho: String,
}

struct MoneyProvisionContextChirho<'context_chirho> {
    storage_chirho: &'context_chirho FsLedgerStorageChirho,
    runtime_signers_chirho: &'context_chirho HostLedgerSignersChirho,
    issuer_signer_chirho: &'context_chirho OfflineKindIssuerSignerChirho,
    issuer_verify_chirho: &'context_chirho PinnedKindIssuerVerifierChirho,
    membership_chirho: &'context_chirho StaticClusterMembershipChirho,
    activation_verifier_chirho: &'context_chirho PinnedLedgerActivationVerifierChirho,
    activation_authorization_chirho: ResidentLedgerActivationAuthorizationChirho,
    monitor_namespace_root_chirho: &'context_chirho Path,
}

impl fmt::Debug for LedgerRegenesisMoneyStageChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho
            .debug_struct("LedgerRegenesisMoneyStageChirho")
            .field("plan_digest_chirho", &self.plan_digest_chirho)
            .field("proof_chirho", &self.proof_chirho)
            .field("paths_chirho", &"<operator-paths-redacted-chirho>")
            .field("signers_chirho", &"<redacted-chirho>")
            .finish()
    }
}

impl LedgerRegenesisMoneyStageChirho {
    pub fn proof_chirho(&self) -> &LedgerRegenesisMoneyProofChirho {
        &self.proof_chirho
    }

    pub fn staging_parent_name_chirho(&self) -> Option<&str> {
        self.staging_parent_chirho
            .file_name()
            .and_then(|name_chirho| name_chirho.to_str())
    }

    pub fn staged_storage_namespace_root_chirho(&self) -> &Path {
        self.storage_chirho.namespace_root_chirho()
    }

    pub fn staged_monitor_namespace_root_chirho(&self) -> &Path {
        &self.monitor_namespace_root_chirho
    }

    pub fn verified_host_config_chirho(&self) -> &LedgerHostConfigChirho {
        &self.config_chirho
    }

    pub fn reviewed_plan_chirho(&self) -> &LedgerRegenesisPlanV1Chirho {
        &self.plan_chirho
    }

    pub fn runtime_signer_roles_chirho(&self) -> [LedgerSignerRoleChirho; 6] {
        [
            self.runtime_signers_chirho
                .journal_signer_chirho()
                .role_chirho(),
            self.runtime_signers_chirho
                .config_signer_chirho()
                .role_chirho(),
            self.runtime_signers_chirho
                .feeder_signer_chirho()
                .role_chirho(),
            self.runtime_signers_chirho
                .kind_root_signer_chirho()
                .role_chirho(),
            self.runtime_signers_chirho
                .effect_intent_signer_chirho()
                .role_chirho(),
            self.runtime_signers_chirho
                .effect_terminal_signer_chirho()
                .role_chirho(),
        ]
    }
}

/// Produce the exact pre-signed activation artifact in a read-only authoring phase. The caller is
/// responsible for writing the returned canonical bytes to a reviewed create-new artifact.
pub fn author_ledger_regenesis_activation_chirho(
    request_chirho: LedgerRegenesisActivationAuthorRequestChirho<'_>,
) -> LedgerRegenesisResultChirho<LedgerRegenesisActivationArtifactChirho> {
    let verified_plan_chirho = load_verified_plan_chirho(
        request_chirho.selected_root_chirho,
        request_chirho.config_path_chirho,
        request_chirho.plan_path_chirho,
        request_chirho.expected_plan_digest_chirho,
    )?;
    let signer_refs_chirho = host_ledger_signer_refs_from_config_chirho(
        &verified_plan_chirho.config_chirho.signer_secrets_chirho,
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::RuntimeSignerRefusedChirho)?;
    let runtime_signers_chirho = HostLedgerSignersChirho::load_existing_chirho(
        &verified_plan_chirho.selected_root_chirho,
        &signer_refs_chirho,
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::RuntimeSignerRefusedChirho)?;
    let activation_pin_chirho = verified_plan_chirho
        .config_chirho
        .activation_authority_chirho
        .as_ref()
        .ok_or(LedgerRegenesisRefusalChirho::ActivationConfigMissingChirho)?;
    let activation_verifier_chirho =
        PinnedLedgerActivationVerifierChirho::from_config_chirho(activation_pin_chirho)
            .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::ActivationPinMismatchChirho)?;
    let activation_signer_chirho = OfflineLedgerActivationSignerChirho::load_existing_chirho(
        &verified_plan_chirho.selected_root_chirho,
        request_chirho.activation_secret_name_chirho,
        request_chirho.issuer_secret_name_chirho,
        activation_pin_chirho,
        &verified_plan_chirho.config_chirho.kind_issuer_chirho,
        &runtime_signers_chirho,
    )?;
    let membership_chirho = StaticClusterMembershipChirho::from_config_chirho(
        verified_plan_chirho.config_chirho.local_epoch_chirho,
        &verified_plan_chirho.config_chirho.members_chirho,
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::ConfigInvalidChirho)?;
    verify_initial_owner_membership_chirho(&verified_plan_chirho, &membership_chirho)?;
    let (_intent_chirho, statement_chirho) = activation_statement_for_plan_chirho(
        &verified_plan_chirho,
        activation_verifier_chirho.principal_chirho(),
    )?;
    let authorization_chirho =
        activation_signer_chirho.authorize_statement_chirho(statement_chirho.clone())?;
    let authorization_digest_chirho = verify_resident_ledger_activation_authorization_chirho(
        &activation_verifier_chirho,
        &statement_chirho,
        &authorization_chirho,
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::ActivationStatementRefusedChirho)?;
    let canonical_bytes_chirho = canonical_resident_ledger_activation_authorization_chirho(
        &authorization_chirho,
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::ActivationStatementRefusedChirho)?;
    Ok(LedgerRegenesisActivationArtifactChirho {
        authorization_chirho,
        canonical_bytes_chirho,
        authorization_digest_chirho,
    })
}

/// Build H3-A entirely under the non-live staging sibling. All plan/config/key checks complete
/// before `begin_staging_chirho` performs the first write.
///
/// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf6-regenesis-boundary-chirho.md`.
pub fn prepare_money_stage_chirho(
    request_chirho: LedgerRegenesisH3aRequestChirho<'_>,
) -> LedgerRegenesisResultChirho<LedgerRegenesisMoneyStageChirho> {
    let verified_plan_chirho = load_verified_plan_chirho(
        request_chirho.selected_root_chirho,
        request_chirho.config_path_chirho,
        request_chirho.plan_path_chirho,
        request_chirho.expected_plan_digest_chirho,
    )?;
    let signer_refs_chirho = host_ledger_signer_refs_from_config_chirho(
        &verified_plan_chirho.config_chirho.signer_secrets_chirho,
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::RuntimeSignerRefusedChirho)?;
    let runtime_signers_chirho = HostLedgerSignersChirho::load_existing_chirho(
        &verified_plan_chirho.selected_root_chirho,
        &signer_refs_chirho,
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::RuntimeSignerRefusedChirho)?;
    let issuer_verify_chirho = PinnedKindIssuerVerifierChirho::from_config_chirho(
        &verified_plan_chirho.config_chirho.kind_issuer_chirho,
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::IssuerPinMismatchChirho)?;
    let issuer_signer_chirho = OfflineKindIssuerSignerChirho::load_existing_chirho(
        &verified_plan_chirho.selected_root_chirho,
        request_chirho.issuer_secret_name_chirho,
        &verified_plan_chirho.config_chirho.kind_issuer_chirho,
        &runtime_signers_chirho,
    )?;
    let activation_pin_chirho = verified_plan_chirho
        .config_chirho
        .activation_authority_chirho
        .as_ref()
        .ok_or(LedgerRegenesisRefusalChirho::ActivationConfigMissingChirho)?;
    let activation_verifier_chirho =
        PinnedLedgerActivationVerifierChirho::from_config_chirho(activation_pin_chirho)
            .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::ActivationPinMismatchChirho)?;
    let membership_chirho = StaticClusterMembershipChirho::from_config_chirho(
        verified_plan_chirho.config_chirho.local_epoch_chirho,
        &verified_plan_chirho.config_chirho.members_chirho,
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::ConfigInvalidChirho)?;
    verify_initial_owner_membership_chirho(&verified_plan_chirho, &membership_chirho)?;
    let (_intent_chirho, expected_statement_chirho) = activation_statement_for_plan_chirho(
        &verified_plan_chirho,
        activation_verifier_chirho.principal_chirho(),
    )?;
    let activation_authorization_chirho = load_verified_activation_authorization_chirho(
        request_chirho.activation_authorization_path_chirho,
        request_chirho.expected_activation_authorization_digest_chirho,
        &activation_verifier_chirho,
        &expected_statement_chirho,
    )?;

    let begun_stage_chirho = begin_staging_chirho(&verified_plan_chirho)?;
    let provisioned_chirho = provision_money_chirho(
        &verified_plan_chirho,
        MoneyProvisionContextChirho {
            storage_chirho: &begun_stage_chirho.storage_chirho,
            runtime_signers_chirho: &runtime_signers_chirho,
            issuer_signer_chirho: &issuer_signer_chirho,
            issuer_verify_chirho: &issuer_verify_chirho,
            membership_chirho: &membership_chirho,
            activation_verifier_chirho: &activation_verifier_chirho,
            activation_authorization_chirho,
            monitor_namespace_root_chirho: &begun_stage_chirho.monitor_namespace_root_chirho,
        },
    )?;
    Ok(LedgerRegenesisMoneyStageChirho {
        selected_root_chirho: verified_plan_chirho.selected_root_chirho,
        final_parent_chirho: verified_plan_chirho.final_parent_chirho,
        staging_parent_chirho: verified_plan_chirho.staging_parent_chirho,
        monitor_namespace_root_chirho: begun_stage_chirho.monitor_namespace_root_chirho,
        storage_chirho: begun_stage_chirho.storage_chirho,
        config_chirho: verified_plan_chirho.config_chirho,
        runtime_signers_chirho,
        plan_chirho: verified_plan_chirho.plan_chirho,
        plan_digest_chirho: verified_plan_chirho.plan_digest_chirho,
        activation_receipt_chirho: provisioned_chirho.activation_receipt_chirho,
        canary_evidence_digest_chirho: provisioned_chirho.canary_evidence_digest_chirho,
        proof_chirho: provisioned_chirho.proof_chirho,
    })
}

fn verify_initial_owner_membership_chirho(
    verified_plan_chirho: &crate::plan_chirho::VerifiedLedgerRegenesisPlanChirho,
    membership_chirho: &StaticClusterMembershipChirho,
) -> LedgerRegenesisResultChirho<()> {
    let account_chirho = AccountIdChirho {
        owner_chirho: verified_plan_chirho
            .plan_chirho
            .initial_owner_chirho
            .clone(),
        kind_id_chirho: AssetKindIdChirho(verified_plan_chirho.plan_chirho.kind_id_chirho.clone()),
    };
    if !matches!(
        membership_chirho.status_chirho(
            &account_chirho,
            verified_plan_chirho.plan_chirho.local_epoch_chirho,
        ),
        MembershipStatusChirho::MemberChirho
    ) {
        return Err(LedgerRegenesisRefusalChirho::ConfigPlanMismatchChirho);
    }
    Ok(())
}

fn activation_statement_for_plan_chirho(
    verified_plan_chirho: &crate::plan_chirho::VerifiedLedgerRegenesisPlanChirho,
    activation_principal_chirho: &str,
) -> LedgerRegenesisResultChirho<(
    ResidentLedgerMintIntentChirho,
    cairn_ledger_host_chirho::ResidentLedgerActivationStatementChirho,
)> {
    let initial_policy_ref_chirho =
        derive_policy_ref_chirho(&verified_plan_chirho.plan_chirho.initial_policy_chirho)
            .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::PlanPolicyRefusedChirho)?;
    let intent_chirho = activation_intent_chirho(
        verified_plan_chirho,
        &initial_policy_ref_chirho,
        activation_principal_chirho,
    );
    let node_chirho =
        existing_keypair_pubkey_hex_chirho(&verified_plan_chirho.selected_root_chirho)
            .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::RuntimeSignerRefusedChirho)?;
    let group_chirho =
        consistency_group_for_root_chirho(&verified_plan_chirho.selected_root_chirho)
            .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::ConfigInvalidChirho)?;
    let final_storage_namespace_chirho = verified_plan_chirho
        .final_parent_chirho
        .join(&verified_plan_chirho.storage_child_chirho);
    let plan_chirho = &verified_plan_chirho.plan_chirho;
    let statement_chirho =
        resident_ledger_activation_statement_chirho(ResidentLedgerActivationStatementInputChirho {
            root_chirho: &verified_plan_chirho.selected_root_chirho,
            identity_storage_namespace_chirho: &final_storage_namespace_chirho,
            journal_path_chirho: &StoragePathChirho::new_chirho(&plan_chirho.journal_path_chirho),
            cluster_id_chirho: &ClusterIdChirho(plan_chirho.cluster_id_chirho.clone()),
            opening_epoch_chirho: plan_chirho.local_epoch_chirho,
            append_physical_ms_chirho: plan_chirho.mint_physical_ms_chirho,
            elected_node_chirho: &node_chirho,
            consistency_group_chirho: &group_chirho,
            intent_chirho: intent_chirho.clone(),
        })
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::ActivationStatementRefusedChirho)?;
    Ok((intent_chirho, statement_chirho))
}

fn load_verified_activation_authorization_chirho(
    path_chirho: &Path,
    expected_digest_chirho: &str,
    verifier_chirho: &PinnedLedgerActivationVerifierChirho,
    expected_statement_chirho: &cairn_ledger_host_chirho::ResidentLedgerActivationStatementChirho,
) -> LedgerRegenesisResultChirho<ResidentLedgerActivationAuthorizationChirho> {
    let bytes_chirho = read_bounded_regular_authorization_chirho(path_chirho)?;
    let authorization_chirho = parse_canonical_resident_ledger_activation_authorization_chirho(
        &bytes_chirho,
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::ActivationStatementRefusedChirho)?;
    let actual_digest_chirho = verify_resident_ledger_activation_authorization_chirho(
        verifier_chirho,
        expected_statement_chirho,
        &authorization_chirho,
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::ActivationStatementRefusedChirho)?;
    if actual_digest_chirho != expected_digest_chirho {
        return Err(LedgerRegenesisRefusalChirho::ActivationAuthorizationDigestMismatchChirho);
    }
    Ok(authorization_chirho)
}

fn read_bounded_regular_authorization_chirho(
    path_chirho: &Path,
) -> LedgerRegenesisResultChirho<Vec<u8>> {
    read_bounded_regular_file_chirho(
        path_chirho,
        MAX_RESIDENT_LEDGER_ACTIVATION_AUTHORIZATION_BYTES_CHIRHO as u64,
    )
    .map_err(|error_chirho| {
        if error_chirho.kind() == std::io::ErrorKind::InvalidData {
            LedgerRegenesisRefusalChirho::ActivationAuthorizationRefusedChirho
        } else {
            LedgerRegenesisRefusalChirho::ActivationAuthorizationUnavailableChirho
        }
    })
}

fn provision_money_chirho(
    verified_plan_chirho: &crate::plan_chirho::VerifiedLedgerRegenesisPlanChirho,
    context_chirho: MoneyProvisionContextChirho<'_>,
) -> LedgerRegenesisResultChirho<ProvisionedMoneyChirho> {
    let MoneyProvisionContextChirho {
        storage_chirho,
        runtime_signers_chirho,
        issuer_signer_chirho,
        issuer_verify_chirho,
        membership_chirho,
        activation_verifier_chirho,
        activation_authorization_chirho,
        monitor_namespace_root_chirho,
    } = context_chirho;
    let plan_chirho = &verified_plan_chirho.plan_chirho;
    let kind_id_chirho = AssetKindIdChirho(plan_chirho.kind_id_chirho.clone());
    let registry_path_chirho =
        StoragePathChirho::new_chirho(&plan_chirho.kind_registry_path_chirho);
    let journal_path_chirho = StoragePathChirho::new_chirho(&plan_chirho.journal_path_chirho);
    let registry_ports_chirho = KindRegistryPortsChirho {
        storage_chirho,
        registry_root_chirho: runtime_signers_chirho.kind_root_signer_chirho(),
        issuer_verify_chirho,
    };
    append_registry_op_chirho(
        registry_ports_chirho,
        issuer_signer_chirho,
        &registry_path_chirho,
        &plan_chirho.kind_registry_id_chirho,
        &plan_chirho.issuer_principal_chirho,
        KindRegistryOpChirho::RegisterKindChirho {
            kind_id_chirho: kind_id_chirho.clone(),
            policy_chirho: plan_chirho.initial_policy_chirho.clone(),
        },
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::MoneyProvisionRefusedChirho)?;
    let initial_policy_ref_chirho = derive_policy_ref_chirho(&plan_chirho.initial_policy_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::MoneyProvisionRefusedChirho)?;
    let initial_registry_chirho = load_verified_registry_chirho(
        registry_ports_chirho,
        &registry_path_chirho,
        &plan_chirho.kind_registry_id_chirho,
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::MoneyProvisionRefusedChirho)?;
    let initial_authority_chirho =
        PlatformPolicyMintAuthorityChirho::new_chirho(&initial_registry_chirho);
    let elected_membership_chirho = membership_chirho.elected_view_chirho();
    let clock_chirho =
        ResidentLedgerClockChirho::reviewed_chirho(plan_chirho.genesis_physical_ms_chirho);
    let resident_ports_chirho = ResidentLedgerLocalPortsChirho {
        storage_chirho,
        signer_chirho: runtime_signers_chirho.journal_signer_chirho(),
        clock_chirho: &clock_chirho,
        membership_chirho: &elected_membership_chirho,
        kind_registry_chirho: &initial_registry_chirho,
        authority_chirho: &initial_authority_chirho,
    };
    let node_chirho = NodeIdChirho(
        existing_keypair_pubkey_hex_chirho(&verified_plan_chirho.selected_root_chirho)
            .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::MoneyProvisionRefusedChirho)?,
    );
    let group_chirho =
        consistency_group_for_root_chirho(&verified_plan_chirho.selected_root_chirho)
            .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::MoneyProvisionRefusedChirho)?;
    let election_state_root_chirho =
        monitor_namespace_root_chirho.join(H3_ELECTION_STATE_DIR_CHIRHO);
    let elector_chirho = RaftWriterElectorChirho::new_durable_single_node_chirho(
        election_state_root_chirho,
        node_chirho.clone(),
        group_chirho.clone(),
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::MoneyProvisionRefusedChirho)?
    .with_message_authentication_chirho(verified_plan_chirho.selected_root_chirho.clone())
    .with_leadership_warmup_lease_chirho();
    elector_chirho
        .campaign_chirho()
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::MoneyProvisionRefusedChirho)?;
    for _warmup_tick_chirho in 0..H3_SINGLE_NODE_WARMUP_TICKS_CHIRHO {
        let _outbound_chirho = elector_chirho.tick_chirho();
    }
    let intent_chirho = activation_intent_chirho(
        verified_plan_chirho,
        &initial_policy_ref_chirho,
        activation_verifier_chirho.principal_chirho(),
    );
    let final_storage_namespace_chirho = verified_plan_chirho
        .final_parent_chirho
        .join(&verified_plan_chirho.storage_child_chirho);
    let local_authority_chirho = elector_chirho.local_append_authority_handle_chirho();
    let activation_receipt_chirho =
        activate_reviewed_h3_chirho(ResidentLedgerActivationInputChirho {
            root_chirho: &verified_plan_chirho.selected_root_chirho,
            identity_storage_namespace_chirho: &final_storage_namespace_chirho,
            ports_chirho: resident_ports_chirho,
            journal_path_chirho: journal_path_chirho.clone(),
            cluster_id_chirho: ClusterIdChirho(plan_chirho.cluster_id_chirho.clone()),
            opening_epoch_chirho: plan_chirho.local_epoch_chirho,
            append_physical_ms_chirho: plan_chirho.mint_physical_ms_chirho,
            local_authority_chirho,
            verifier_chirho: activation_verifier_chirho,
            intent_chirho,
            authorization_chirho: activation_authorization_chirho,
        })
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::MoneyProvisionRefusedChirho)?;
    let recorded_canary_chirho = record_activation_canary_chirho(
        verified_plan_chirho,
        monitor_namespace_root_chirho,
        &elector_chirho,
        &group_chirho,
        &node_chirho,
        &activation_receipt_chirho,
    )?;

    append_registry_op_chirho(
        registry_ports_chirho,
        issuer_signer_chirho,
        &registry_path_chirho,
        &plan_chirho.kind_registry_id_chirho,
        &plan_chirho.issuer_principal_chirho,
        KindRegistryOpChirho::AmendKindPolicyChirho {
            kind_id_chirho: kind_id_chirho.clone(),
            supersedes_ref_chirho: initial_policy_ref_chirho.clone(),
            policy_chirho: plan_chirho.amended_policy_chirho.clone(),
        },
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::MoneyProvisionRefusedChirho)?;
    let current_policy_ref_chirho = derive_policy_ref_chirho(&plan_chirho.amended_policy_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::MoneyProvisionRefusedChirho)?;
    let amended_registry_chirho = load_verified_registry_chirho(
        registry_ports_chirho,
        &registry_path_chirho,
        &plan_chirho.kind_registry_id_chirho,
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::MoneyProvisionRefusedChirho)?;
    if amended_registry_chirho
        .kinds_chirho
        .get(&kind_id_chirho)
        .map(|projection_chirho| &projection_chirho.current_ref_chirho)
        != Some(&current_policy_ref_chirho)
    {
        return Err(LedgerRegenesisRefusalChirho::MoneyProvisionRefusedChirho);
    }
    let amended_authority_chirho =
        PlatformPolicyMintAuthorityChirho::new_chirho(&amended_registry_chirho);
    let amended_journal_ports_chirho = JournalPortsChirho {
        storage_chirho,
        signer_chirho: runtime_signers_chirho.journal_signer_chirho(),
        clock_chirho: &clock_chirho,
        membership_chirho: &elected_membership_chirho,
        kind_registry_chirho: &amended_registry_chirho,
        authority_chirho: &amended_authority_chirho,
    };
    let replayed_chirho = LedgerJournalChirho::open_read_only_chirho(
        amended_journal_ports_chirho,
        journal_path_chirho.clone(),
        &ClusterIdChirho(plan_chirho.cluster_id_chirho.clone()),
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::MoneyProvisionRefusedChirho)?;
    let replayed_supply_chirho = replayed_chirho.supply_chirho(&kind_id_chirho);
    if replayed_supply_chirho != plan_chirho.initial_mint_amount_chirho {
        return Err(LedgerRegenesisRefusalChirho::MoneyProvisionRefusedChirho);
    }
    let stale_policy_classified_superseded_chirho = matches!(
        amended_registry_chirho.resolve_chirho(&initial_policy_ref_chirho),
        KindResolutionChirho::SupersededChirho
    );
    if !stale_policy_classified_superseded_chirho {
        return Err(LedgerRegenesisRefusalChirho::StalePolicyWrongRefusalChirho);
    }
    let activation_chirho = LedgerRegenesisActivationProofChirho {
        plan_digest_chirho: activation_receipt_chirho.plan_digest_chirho.clone(),
        append_seq_chirho: activation_receipt_chirho.append_seq_chirho,
        append_record_digest_chirho: activation_receipt_chirho
            .append_record_digest_chirho
            .clone(),
        append_hlc_physical_ms_chirho: activation_receipt_chirho.append_hlc_physical_ms_chirho,
        append_hlc_logical_chirho: activation_receipt_chirho.append_hlc_logical_chirho,
        process_generation_chirho: activation_receipt_chirho.process_generation_chirho,
        durable_term_chirho: activation_receipt_chirho.durable_term_chirho,
        fence_epoch_chirho: activation_receipt_chirho.fence_epoch_chirho,
    };
    Ok(ProvisionedMoneyChirho {
        proof_chirho: LedgerRegenesisMoneyProofChirho {
            plan_digest_chirho: verified_plan_chirho.plan_digest_chirho.clone(),
            initial_policy_ref_chirho,
            current_policy_ref_chirho,
            initial_mint_amount_chirho: plan_chirho.initial_mint_amount_chirho,
            replayed_supply_chirho,
            stale_policy_classified_superseded_chirho,
            activation_chirho,
            canary_chirho: recorded_canary_chirho.proof_chirho,
        },
        activation_receipt_chirho,
        canary_evidence_digest_chirho: recorded_canary_chirho.evidence_digest_chirho,
    })
}

fn activation_intent_chirho(
    verified_plan_chirho: &crate::plan_chirho::VerifiedLedgerRegenesisPlanChirho,
    initial_policy_ref_chirho: &AssetKindRefChirho,
    activation_principal_chirho: &str,
) -> ResidentLedgerMintIntentChirho {
    ResidentLedgerMintIntentChirho {
        plan_digest_chirho: verified_plan_chirho.plan_digest_chirho.clone(),
        activation_principal_chirho: activation_principal_chirho.to_owned(),
        initial_owner_chirho: verified_plan_chirho
            .plan_chirho
            .initial_owner_chirho
            .clone(),
        kind_id_chirho: AssetKindIdChirho(verified_plan_chirho.plan_chirho.kind_id_chirho.clone()),
        kind_policy_ref_chirho: initial_policy_ref_chirho.clone(),
        amount_chirho: verified_plan_chirho.plan_chirho.initial_mint_amount_chirho,
        idempotency_key_chirho: format!(
            "regenesis-initial-mint-{}-chirho",
            &verified_plan_chirho.plan_digest_chirho[..24]
        ),
    }
}

/// Records the first anchored canary observation for the CF8 canary-window workflow.
fn record_activation_canary_chirho(
    verified_plan_chirho: &crate::plan_chirho::VerifiedLedgerRegenesisPlanChirho,
    monitor_namespace_root_chirho: &Path,
    elector_chirho: &RaftWriterElectorChirho,
    group_chirho: &cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho,
    node_chirho: &NodeIdChirho,
    activation_receipt_chirho: &ResidentLedgerActivationReceiptChirho,
) -> LedgerRegenesisResultChirho<RecordedActivationCanaryChirho> {
    let append_cut_chirho = ShadowCanaryAppendCutChirho {
        append_seq_chirho: activation_receipt_chirho.append_seq_chirho,
        append_record_digest_chirho: activation_receipt_chirho
            .append_record_digest_chirho
            .0
            .clone(),
        append_hlc_physical_ms_chirho: activation_receipt_chirho.append_hlc_physical_ms_chirho,
        append_hlc_logical_chirho: activation_receipt_chirho.append_hlc_logical_chirho,
        process_generation_chirho: activation_receipt_chirho.process_generation_chirho,
        durable_term_chirho: activation_receipt_chirho.durable_term_chirho,
        fence_epoch_chirho: activation_receipt_chirho.fence_epoch_chirho,
        fence_group_digest_chirho: activation_receipt_chirho.fence_group_digest_chirho.clone(),
    };
    // The append cut retains the reviewed dormant plan HLC. This separately signed field records
    // when the post-activation election observation was actually made on the writer host.
    let observed_at_ms_chirho = activation_observation_wall_ms_chirho()?;
    let observation_chirho = observe_shadow_canary_chirho(
        elector_chirho,
        group_chirho,
        node_chirho,
        append_cut_chirho.clone(),
        observed_at_ms_chirho,
    );
    if !observation_chirho.cutover_would_permit_chirho {
        return Err(LedgerRegenesisRefusalChirho::MoneyProvisionRefusedChirho);
    }
    let evidence_store_chirho = ShadowCanaryEvidenceStoreChirho::create_activation_chirho(
        &monitor_namespace_root_chirho.join(SHADOW_CANARY_EVIDENCE_DIR_CHIRHO),
        &verified_plan_chirho.selected_root_chirho,
        group_chirho.clone(),
        node_chirho.clone(),
        ShadowCanaryActivationAnchorInputChirho {
            activation_authorization_digest_chirho: activation_receipt_chirho
                .authorization_digest_chirho
                .clone(),
            activation_plan_digest_chirho: activation_receipt_chirho.plan_digest_chirho.clone(),
            resident_identity_digest_chirho: activation_receipt_chirho
                .resident_identity_digest_chirho
                .clone(),
            activation_append_cut_chirho: append_cut_chirho.clone(),
        },
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::MoneyProvisionRefusedChirho)?;
    let evidence_chirho = evidence_store_chirho
        .append_observation_chirho(observation_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::MoneyProvisionRefusedChirho)?;
    let generation_store_chirho = ShadowCanaryGenerationStoreChirho::open_existing_chirho(
        &monitor_namespace_root_chirho.join(SHADOW_CANARY_EVIDENCE_DIR_CHIRHO),
        &verified_plan_chirho.selected_root_chirho,
        group_chirho.clone(),
        node_chirho.clone(),
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::MoneyProvisionRefusedChirho)?;
    let current_generation_chirho = generation_store_chirho
        .verify_current_read_only_chirho()
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::MoneyProvisionRefusedChirho)?;
    let window_chirho = current_generation_chirho
        .require_generation_zero_window_chirho()
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::MoneyProvisionRefusedChirho)?;
    if window_chirho.latest_seq_chirho != evidence_chirho.seq_chirho
        || window_chirho.window_len_chirho != 1
        || window_chirho.permit_count_chirho != 1
        || window_chirho.refusal_count_chirho != 0
        || window_chirho.latest_fence_epoch_chirho != activation_receipt_chirho.fence_epoch_chirho
        || window_chirho.latest_append_cut_chirho != append_cut_chirho
        || window_chirho.activation_anchor_digest_chirho.is_none()
    {
        return Err(LedgerRegenesisRefusalChirho::MoneyProvisionRefusedChirho);
    }
    Ok(RecordedActivationCanaryChirho {
        evidence_digest_chirho: window_chirho.latest_evidence_digest_chirho.clone(),
        proof_chirho: LedgerRegenesisCanaryProofChirho {
            evidence_seq_chirho: evidence_chirho.seq_chirho,
            window_len_chirho: window_chirho.window_len_chirho,
            permit_count_chirho: window_chirho.permit_count_chirho,
            refusal_count_chirho: window_chirho.refusal_count_chirho,
            append_seq_chirho: activation_receipt_chirho.append_seq_chirho,
            append_record_digest_chirho: activation_receipt_chirho
                .append_record_digest_chirho
                .clone(),
            durable_term_chirho: activation_receipt_chirho.durable_term_chirho,
            fence_epoch_chirho: activation_receipt_chirho.fence_epoch_chirho,
        },
    })
}
