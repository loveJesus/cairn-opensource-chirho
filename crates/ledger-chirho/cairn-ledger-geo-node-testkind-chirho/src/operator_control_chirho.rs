// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Filesystem-custodied operator control for the test-kind geo winner.
//!
//! Renamed from "CF7 operator control" on 2026-08-19 when CF8 tenant-migration activation joined it.
//! The wire type names keep their `Cf7` spelling because they are a shipped schema and renaming them
//! would be a compatibility break for no gain — but the MODULE is the test-kind winner's operator
//! surface, and a description that named only its first user would under-describe what it holds.
//!
//! The socket is deliberately separate from the mesh election/relay listener. Its live adapter
//! holds clones of the already-composed shared-elector effect runtime and verified host; it cannot
//! open, campaign, or tick an elector. Filesystem custody (0700 parent, 0600 socket) is the request
//! authorization, so no bearer secret or remotely reachable money endpoint is introduced.
//! Workflows:
//! - `spec-chirho/workflows-chirho/projection-chirho/cf7-read-composition-design-chirho.md`.
//! - `spec-chirho/workflows-chirho/distributed-ha-chirho/healing-drills-chirho/cf8-canary-window-loss-sequence-chirho.md`.

use anyhow::{bail, Context, Result};
use cairn_ledger_host_chirho::{
    ResidentTestkindLossWitnessOutcomeChirho, ResidentTestkindLossWitnessPhaseChirho,
    ResidentTestkindLossWitnessRefusalChirho, TenantMigrationDestinationRecordChirho,
    TenantMigrationWriterAdoptionRecordChirho,
};
use cairn_serve_runtime_chirho::{
    activate_current_ledger_host_tenant_migration_target_chirho,
    begin_current_ledger_host_tenant_migration_source_fence_chirho,
    execute_current_ledger_host_testkind_loss_witness_chirho,
    execute_deposed_sink_ledger_host_testkind_loss_witness_chirho,
    execute_reviewed_current_ledger_host_postgres_compensation_chirho,
    execute_sustained_ledger_host_testkind_loss_witness_chirho,
    preview_current_ledger_host_postgres_compensation_chirho,
    replay_completed_current_ledger_host_postgres_compensation_chirho,
    CurrentPostgresCompensationExecutionChirho, CurrentPostgresCompensationPreviewChirho,
    LedgerConservationCycleOutcomeChirho, LedgerConservationCycleRowChirho,
    LedgerHostProjectionReadPortChirho, SharedLedgerHostPostgresEffectRuntimeChirho,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

#[path = "operator_control_chirho/refusal_mapping_chirho.rs"]
mod refusal_mapping_chirho;
use refusal_mapping_chirho::{
    map_preview_refusal_chirho, map_reviewed_execution_refusal_chirho,
    map_reviewed_replay_refusal_chirho,
};

const TESTKIND_CF7_OPERATOR_REQUEST_SCHEMA_CHIRHO: &str = "testkind-cf7-operator-request-v1-chirho";
const TESTKIND_CF7_OPERATOR_RESPONSE_SCHEMA_CHIRHO: &str =
    "testkind-cf7-operator-response-v1-chirho";
const TESTKIND_CF7_OPERATOR_RUNTIME_DIR_CHIRHO: &str = "runtime-chirho";
const TESTKIND_CF7_OPERATOR_SOCKET_NAME_CHIRHO: &str = "cf7-operator-control-chirho.sock";
const MAX_TESTKIND_CF7_OPERATOR_WIRE_BYTES_CHIRHO: u64 = 64 * 1024;
const MAX_TESTKIND_CF7_OPERATOR_TOKEN_BYTES_CHIRHO: usize = 256;
/// A tenant root path is a filesystem path, not a document. Bounded so a malformed request cannot
/// arrive as an unbounded field on an authority surface.
const MAX_TESTKIND_TARGET_ROOT_PATH_BYTES_CHIRHO: usize = 4096;
// Leave channel setup and cleanup time inside the Phase C wrapper's 120-second budget.
const TESTKIND_CF7_OPERATOR_CLIENT_RESPONSE_TIMEOUT_CHIRHO: Duration = Duration::from_secs(90);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestkindLedgerHeadBindingChirho {
    pub covered_record_count_chirho: u64,
    pub checkpoint_digest_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestkindCompensationExecutionEvidenceChirho {
    pub execution_chirho: CurrentPostgresCompensationExecutionChirho,
    pub post_compensation_head_chirho: TestkindLedgerHeadBindingChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestkindCf7OperatorRequestChirho {
    pub schema_chirho: String,
    pub operation_chirho: TestkindCf7OperatorOperationChirho,
}

impl TestkindCf7OperatorRequestChirho {
    pub fn preview_chirho(app_chirho: String, owner_chirho: String) -> Self {
        Self {
            schema_chirho: TESTKIND_CF7_OPERATOR_REQUEST_SCHEMA_CHIRHO.to_owned(),
            operation_chirho: TestkindCf7OperatorOperationChirho::PreviewChirho {
                app_chirho,
                owner_chirho,
            },
        }
    }

    pub fn execute_chirho(
        app_chirho: String,
        owner_chirho: String,
        reviewed_preview_chirho: CurrentPostgresCompensationPreviewChirho,
    ) -> Self {
        Self {
            schema_chirho: TESTKIND_CF7_OPERATOR_REQUEST_SCHEMA_CHIRHO.to_owned(),
            operation_chirho: TestkindCf7OperatorOperationChirho::ExecuteChirho {
                app_chirho,
                owner_chirho,
                reviewed_preview_chirho,
            },
        }
    }

    pub fn replay_chirho(
        app_chirho: String,
        owner_chirho: String,
        expected_execution_chirho: TestkindCompensationExecutionEvidenceChirho,
    ) -> Self {
        Self {
            schema_chirho: TESTKIND_CF7_OPERATOR_REQUEST_SCHEMA_CHIRHO.to_owned(),
            operation_chirho: TestkindCf7OperatorOperationChirho::ReplayChirho {
                app_chirho,
                owner_chirho,
                expected_execution_chirho,
            },
        }
    }

    pub fn conservation_read_chirho(expected_head_chirho: TestkindLedgerHeadBindingChirho) -> Self {
        Self {
            schema_chirho: TESTKIND_CF7_OPERATOR_REQUEST_SCHEMA_CHIRHO.to_owned(),
            operation_chirho: TestkindCf7OperatorOperationChirho::ConservationReadChirho {
                expected_head_chirho,
            },
        }
    }

    /// Ask the live winner to begin an attempt and fence the source toward an authorized target.
    pub fn migration_begin_source_fence_chirho(
        target_root_chirho: String,
        destination_chirho: TenantMigrationDestinationRecordChirho,
    ) -> Self {
        Self::migration_begin_source_fence_with_writer_adoption_chirho(
            target_root_chirho,
            destination_chirho,
            None,
        )
    }

    pub fn migration_begin_source_fence_with_writer_adoption_chirho(
        target_root_chirho: String,
        destination_chirho: TenantMigrationDestinationRecordChirho,
        writer_adoption_chirho: Option<TenantMigrationWriterAdoptionRecordChirho>,
    ) -> Self {
        Self {
            schema_chirho: TESTKIND_CF7_OPERATOR_REQUEST_SCHEMA_CHIRHO.to_owned(),
            operation_chirho: TestkindCf7OperatorOperationChirho::MigrationBeginSourceFenceChirho {
                target_root_chirho,
                destination_chirho: Box::new(destination_chirho),
                writer_adoption_chirho: writer_adoption_chirho.map(Box::new),
            },
        }
    }

    /// Ask the live winner to activate a tenant-root migration target.
    pub fn migration_activate_target_chirho(target_root_chirho: String) -> Self {
        Self {
            schema_chirho: TESTKIND_CF7_OPERATOR_REQUEST_SCHEMA_CHIRHO.to_owned(),
            operation_chirho: TestkindCf7OperatorOperationChirho::MigrationActivateTargetChirho {
                target_root_chirho,
            },
        }
    }

    pub fn loss_witness_current_chirho(
        phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    ) -> Self {
        Self {
            schema_chirho: TESTKIND_CF7_OPERATOR_REQUEST_SCHEMA_CHIRHO.to_owned(),
            operation_chirho: TestkindCf7OperatorOperationChirho::LossWitnessCurrentChirho {
                phase_chirho,
            },
        }
    }

    pub fn loss_witness_sustained_chirho(
        phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    ) -> Self {
        Self {
            schema_chirho: TESTKIND_CF7_OPERATOR_REQUEST_SCHEMA_CHIRHO.to_owned(),
            operation_chirho: TestkindCf7OperatorOperationChirho::LossWitnessSustainedChirho {
                phase_chirho,
            },
        }
    }

    pub fn loss_witness_deposed_sink_chirho(
        phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    ) -> Self {
        Self {
            schema_chirho: TESTKIND_CF7_OPERATOR_REQUEST_SCHEMA_CHIRHO.to_owned(),
            operation_chirho: TestkindCf7OperatorOperationChirho::LossWitnessDeposedSinkChirho {
                phase_chirho,
            },
        }
    }

    fn validate_chirho(&self) -> std::result::Result<(), TestkindCf7OperatorRefusalChirho> {
        if self.schema_chirho != TESTKIND_CF7_OPERATOR_REQUEST_SCHEMA_CHIRHO {
            return Err(TestkindCf7OperatorRefusalChirho::WrongSchemaChirho);
        }
        match &self.operation_chirho {
            TestkindCf7OperatorOperationChirho::PreviewChirho {
                app_chirho,
                owner_chirho,
            }
            | TestkindCf7OperatorOperationChirho::ExecuteChirho {
                app_chirho,
                owner_chirho,
                ..
            }
            | TestkindCf7OperatorOperationChirho::ReplayChirho {
                app_chirho,
                owner_chirho,
                ..
            } => {
                validate_token_chirho(app_chirho)?;
                validate_token_chirho(owner_chirho)?;
            }
            TestkindCf7OperatorOperationChirho::ConservationReadChirho {
                expected_head_chirho,
            } => validate_head_chirho(expected_head_chirho)?,
            TestkindCf7OperatorOperationChirho::MigrationActivateTargetChirho {
                target_root_chirho,
            } => validate_target_root_path_chirho(target_root_chirho)?,
            // Only the PATH is shape-validated here. The destination record is not checked at this
            // layer on purpose: it is verified against the node's configured authority key, the
            // tenant identity and the source root digest inside the resident actor, and a socket
            // that pre-approved any part of it would be asserting authority it does not hold.
            TestkindCf7OperatorOperationChirho::MigrationBeginSourceFenceChirho {
                target_root_chirho,
                ..
            } => validate_target_root_path_chirho(target_root_chirho)?,
            TestkindCf7OperatorOperationChirho::LossWitnessCurrentChirho { .. }
            | TestkindCf7OperatorOperationChirho::LossWitnessSustainedChirho { .. }
            | TestkindCf7OperatorOperationChirho::LossWitnessDeposedSinkChirho { .. } => {}
        }
        if let TestkindCf7OperatorOperationChirho::ReplayChirho {
            expected_execution_chirho,
            ..
        } = &self.operation_chirho
        {
            validate_head_chirho(&expected_execution_chirho.post_compensation_head_chirho)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation_chirho", deny_unknown_fields)]
pub enum TestkindCf7OperatorOperationChirho {
    #[serde(rename = "preview-chirho")]
    PreviewChirho {
        app_chirho: String,
        owner_chirho: String,
    },
    #[serde(rename = "execute-chirho")]
    ExecuteChirho {
        app_chirho: String,
        owner_chirho: String,
        reviewed_preview_chirho: CurrentPostgresCompensationPreviewChirho,
    },
    #[serde(rename = "replay-chirho")]
    ReplayChirho {
        app_chirho: String,
        owner_chirho: String,
        expected_execution_chirho: TestkindCompensationExecutionEvidenceChirho,
    },
    #[serde(rename = "conservation-read-chirho")]
    ConservationReadChirho {
        expected_head_chirho: TestkindLedgerHeadBindingChirho,
    },
    #[serde(rename = "loss-witness-current-chirho")]
    LossWitnessCurrentChirho {
        phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    },
    #[serde(rename = "loss-witness-sustained-chirho")]
    LossWitnessSustainedChirho {
        phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    },
    #[serde(rename = "loss-witness-deposed-sink-chirho")]
    LossWitnessDeposedSinkChirho {
        phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    },
    /// Activate a tenant-root migration target on the live winner.
    ///
    /// Carries ONLY a path. The preliminary check cannot cross a wire — it has private fields, no
    /// `Serialize`, and is issued only when all three verdicts pass over real evidence — so the
    /// adapter computes it from the target root rather than accepting an operator's word for it.
    #[serde(rename = "migration-activate-target-chirho")]
    MigrationActivateTargetChirho { target_root_chirho: String },
    /// Begin a tenant-root migration attempt and fence the source.
    ///
    /// Carries the externally signed destination authorization, which is exactly the kind of value
    /// that SHOULD cross this wire: minted by an authority that is not this node, verifiable here,
    /// and useless if forged. Contrast the preliminary check, which never crosses it.
    #[serde(rename = "migration-begin-source-fence-chirho")]
    MigrationBeginSourceFenceChirho {
        target_root_chirho: String,
        destination_chirho: Box<TenantMigrationDestinationRecordChirho>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        writer_adoption_chirho: Option<Box<TenantMigrationWriterAdoptionRecordChirho>>,
    },
}

/// The socket's OWN shape for an activation result.
///
/// `ResidentTenantMigrationTargetActivatedStatusChirho` is deliberately not `Serialize`: an internal
/// authority value should not become a wire contract by accident. This carries the two identities an
/// operator needs to correlate the run, and the phase as a fixed string this module owns.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestkindTenantMigrationActivatedChirho {
    pub attempt_digest_chirho: String,
    pub checkpoint_ref_chirho: String,
    pub phase_chirho: String,
}

/// The socket's OWN shape for a source-fence result.
///
/// Its own type rather than reusing the activated shape, for the reason the resident layer already
/// gives about the same pair: a value named for an ACTIVATION that carried a fenced phase would
/// assert the opposite of what it holds. Carries the marker generation too, because that is the
/// number an operator needs to tell one fence attempt from a retry of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestkindTenantMigrationSourceFencedChirho {
    pub attempt_digest_chirho: String,
    pub checkpoint_ref_chirho: String,
    pub phase_chirho: String,
    pub marker_activation_generation_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestkindCf7OperatorResponseChirho {
    pub schema_chirho: String,
    pub outcome_chirho: TestkindCf7OperatorOutcomeChirho,
}

impl TestkindCf7OperatorResponseChirho {
    fn outcome_chirho(outcome_chirho: TestkindCf7OperatorOutcomeChirho) -> Self {
        Self {
            schema_chirho: TESTKIND_CF7_OPERATOR_RESPONSE_SCHEMA_CHIRHO.to_owned(),
            outcome_chirho,
        }
    }

    fn refused_chirho(refusal_chirho: TestkindCf7OperatorRefusalChirho) -> Self {
        Self::outcome_chirho(TestkindCf7OperatorOutcomeChirho::RefusedChirho { refusal_chirho })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome_chirho", deny_unknown_fields)]
pub enum TestkindCf7OperatorOutcomeChirho {
    #[serde(rename = "migration-activated-chirho")]
    MigrationActivatedChirho {
        activated_chirho: TestkindTenantMigrationActivatedChirho,
    },
    #[serde(rename = "migration-source-fenced-chirho")]
    MigrationSourceFencedChirho {
        fenced_chirho: TestkindTenantMigrationSourceFencedChirho,
    },
    #[serde(rename = "preview-chirho")]
    PreviewChirho {
        preview_chirho: CurrentPostgresCompensationPreviewChirho,
    },
    #[serde(rename = "executed-chirho")]
    ExecutedChirho {
        evidence_chirho: TestkindCompensationExecutionEvidenceChirho,
    },
    #[serde(rename = "replayed-chirho")]
    ReplayedChirho {
        evidence_chirho: TestkindCompensationExecutionEvidenceChirho,
    },
    #[serde(rename = "conservation-green-chirho")]
    ConservationGreenChirho {
        row_chirho: LedgerConservationCycleRowChirho,
    },
    #[serde(rename = "loss-witness-chirho")]
    LossWitnessChirho {
        witness_chirho: ResidentTestkindLossWitnessOutcomeChirho,
    },
    #[serde(rename = "refused-chirho")]
    RefusedChirho {
        refusal_chirho: TestkindCf7OperatorRefusalChirho,
    },
}

// `Copy` was dropped when activation gained a reason-carrying refusal. A refusal that cannot
// say WHY is worse than one that must be cloned, and this enum is read once per request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestkindCf7OperatorRefusalChirho {
    #[serde(rename = "wrong-schema-chirho")]
    WrongSchemaChirho,
    #[serde(rename = "noncanonical-request-chirho")]
    NoncanonicalRequestChirho,
    #[serde(rename = "request-too-large-chirho")]
    RequestTooLargeChirho,
    #[serde(rename = "invalid-token-chirho")]
    InvalidTokenChirho,
    #[serde(rename = "invalid-head-chirho")]
    InvalidHeadChirho,
    /// Activation refused. Carries the reason as a fixed string this module owns rather than the
    /// internal refusal enum, for the same reason the success shape is local: an authority type
    /// should not become a wire contract by accident.
    #[serde(rename = "migration-activation-refused-chirho")]
    MigrationActivationRefusedChirho { reason_chirho: String },
    #[serde(rename = "preview-refused-chirho")]
    PreviewRefusedChirho,
    #[serde(rename = "execution-refused-chirho")]
    ExecutionRefusedChirho,
    #[serde(rename = "compensation-current-app-refused-chirho")]
    CompensationCurrentAppRefusedChirho,
    #[serde(rename = "compensation-current-promotion-refused-chirho")]
    CompensationCurrentPromotionRefusedChirho,
    #[serde(rename = "compensation-current-plan-refused-chirho")]
    CompensationCurrentPlanRefusedChirho,
    #[serde(rename = "compensation-no-eligible-plan-effect-chirho")]
    CompensationNoEligiblePlanEffectChirho,
    #[serde(rename = "compensation-multiple-eligible-plan-effects-chirho")]
    CompensationMultipleEligiblePlanEffectsChirho,
    #[serde(rename = "compensation-stale-authority-chirho")]
    CompensationStaleAuthorityChirho,
    #[serde(rename = "compensation-no-eligible-journal-effect-chirho")]
    CompensationNoEligibleJournalEffectChirho,
    #[serde(rename = "compensation-multiple-eligible-journal-effects-chirho")]
    CompensationMultipleEligibleJournalEffectsChirho,
    #[serde(rename = "compensation-original-effect-evidence-refused-chirho")]
    CompensationOriginalEffectEvidenceRefusedChirho,
    #[serde(rename = "compensation-provider-preview-refused-chirho")]
    CompensationProviderPreviewRefusedChirho,
    #[serde(rename = "compensation-current-price-refused-chirho")]
    CompensationCurrentPriceRefusedChirho,
    #[serde(rename = "compensation-existing-binding-refused-chirho")]
    CompensationExistingBindingRefusedChirho,
    #[serde(rename = "compensation-authorization-refused-chirho")]
    CompensationAuthorizationRefusedChirho,
    #[serde(rename = "compensation-pending-manual-chirho")]
    CompensationPendingManualChirho,
    #[serde(rename = "compensation-in-doubt-chirho")]
    CompensationInDoubtChirho,
    #[serde(rename = "compensation-terminal-refused-chirho")]
    CompensationTerminalRefusedChirho,
    #[serde(rename = "compensation-execution-sink-term-no-accepted-winner-refused-chirho")]
    CompensationExecutionSinkTermNoAcceptedWinnerRefusedChirho,
    #[serde(rename = "compensation-execution-sink-term-stale-winner-refused-chirho")]
    CompensationExecutionSinkTermStaleWinnerRefusedChirho,
    #[serde(rename = "compensation-execution-sink-term-unseen-winner-refused-chirho")]
    CompensationExecutionSinkTermUnseenWinnerRefusedChirho,
    #[serde(rename = "compensation-execution-ordinary-term-inputs-unavailable-chirho")]
    CompensationExecutionOrdinaryTermInputsUnavailableChirho,
    #[serde(rename = "compensation-execution-ordinary-term-acceptance-refused-chirho")]
    CompensationExecutionOrdinaryTermAcceptanceRefusedChirho,
    #[serde(rename = "compensation-execution-committed-evidence-pending-chirho")]
    CompensationExecutionCommittedEvidencePendingChirho,
    #[serde(rename = "compensation-execution-refused-chirho")]
    CompensationExecutionRefusedChirho,
    #[serde(rename = "postgres-effect-config-unavailable-chirho")]
    PostgresEffectConfigUnavailableChirho,
    #[serde(rename = "postgres-connection-secret-unavailable-chirho")]
    PostgresConnectionSecretUnavailableChirho,
    #[serde(rename = "postgres-connection-outside-local-phase-b-chirho")]
    PostgresConnectionOutsideLocalPhaseBChirho,
    #[serde(rename = "postgres-connection-unavailable-chirho")]
    PostgresConnectionUnavailableChirho,
    #[serde(rename = "postgres-database-schema-unavailable-chirho")]
    PostgresDatabaseSchemaUnavailableChirho,
    #[serde(rename = "postgres-adapter-custody-unavailable-chirho")]
    PostgresAdapterCustodyUnavailableChirho,
    #[serde(rename = "postgres-billing-kind-unavailable-chirho")]
    PostgresBillingKindUnavailableChirho,
    #[serde(rename = "postgres-projection-route-unavailable-chirho")]
    PostgresProjectionRouteUnavailableChirho,
    #[serde(rename = "postgres-projection-feed-unavailable-chirho")]
    PostgresProjectionFeedUnavailableChirho,
    #[serde(rename = "postgres-provider-lock-unavailable-chirho")]
    PostgresProviderLockUnavailableChirho,
    #[serde(rename = "postgres-blocking-dispatch-unavailable-chirho")]
    PostgresBlockingDispatchUnavailableChirho,
    #[serde(rename = "postgres-foreign-root-chirho")]
    PostgresForeignRootChirho,
    #[serde(rename = "postgres-contract-law-refused-chirho")]
    PostgresContractLawRefusedChirho,
    #[serde(rename = "postgres-composition-unavailable-chirho")]
    PostgresCompositionUnavailableChirho,
    #[serde(rename = "postgres-verified-context-unavailable-chirho")]
    PostgresVerifiedContextUnavailableChirho,
    #[serde(rename = "postgres-invocation-scope-unavailable-chirho")]
    PostgresInvocationScopeUnavailableChirho,
    #[serde(rename = "postgres-bootstrap-refused-chirho")]
    PostgresBootstrapRefusedChirho,
    #[serde(rename = "postgres-custody-unavailable-chirho")]
    PostgresCustodyUnavailableChirho,
    #[serde(rename = "postgres-money-policy-refused-chirho")]
    PostgresMoneyPolicyRefusedChirho,
    #[serde(rename = "postgres-invocation-obligation-conflict-chirho")]
    PostgresInvocationObligationConflictChirho,
    #[serde(rename = "postgres-provider-outcome-in-doubt-chirho")]
    PostgresProviderOutcomeInDoubtChirho,
    #[serde(rename = "reviewed-preview-changed-chirho")]
    ReviewedPreviewChangedChirho,
    #[serde(rename = "reviewed-preview-not-executable-chirho")]
    ReviewedPreviewNotExecutableChirho,
    #[serde(rename = "replay-refused-chirho")]
    ReplayRefusedChirho,
    #[serde(rename = "replay-not-completed-chirho")]
    ReplayNotCompletedChirho,
    #[serde(rename = "replay-execution-changed-chirho")]
    ReplayExecutionChangedChirho,
    #[serde(rename = "replay-head-moved-chirho")]
    ReplayHeadMovedChirho,
    #[serde(rename = "conservation-refused-chirho")]
    ConservationRefusedChirho,
    #[serde(rename = "conservation-not-green-chirho")]
    ConservationNotGreenChirho,
    #[serde(rename = "conservation-empty-chirho")]
    ConservationEmptyChirho,
    #[serde(rename = "conservation-head-mismatch-chirho")]
    ConservationHeadMismatchChirho,
    #[serde(rename = "loss-witness-refused-chirho")]
    LossWitnessRefusedChirho {
        refusal_chirho: ResidentTestkindLossWitnessRefusalChirho,
    },
}

trait TestkindCf7OperatorAuthorityChirho: Send + Sync {
    fn preview_chirho(
        &self,
        app_chirho: &str,
        owner_chirho: &str,
    ) -> std::result::Result<
        CurrentPostgresCompensationPreviewChirho,
        TestkindCf7OperatorRefusalChirho,
    >;

    fn execute_chirho(
        &self,
        app_chirho: &str,
        owner_chirho: &str,
        reviewed_preview_chirho: &CurrentPostgresCompensationPreviewChirho,
    ) -> std::result::Result<
        TestkindCompensationExecutionEvidenceChirho,
        TestkindCf7OperatorRefusalChirho,
    >;

    fn replay_chirho(
        &self,
        app_chirho: &str,
        owner_chirho: &str,
        expected_execution_chirho: &TestkindCompensationExecutionEvidenceChirho,
    ) -> std::result::Result<
        TestkindCompensationExecutionEvidenceChirho,
        TestkindCf7OperatorRefusalChirho,
    >;

    fn conservation_read_chirho(
        &self,
        expected_head_chirho: &TestkindLedgerHeadBindingChirho,
    ) -> std::result::Result<LedgerConservationCycleRowChirho, TestkindCf7OperatorRefusalChirho>;

    /// Activate a tenant-root migration target on the live winner.
    ///
    /// DEFAULTS TO A REFUSAL, like its siblings and for the same reason: an authority that has not
    /// implemented this cannot be made to activate anything by adding an operation to the wire.
    fn migration_activate_target_chirho(
        &self,
        _target_root_chirho: &str,
    ) -> std::result::Result<TestkindTenantMigrationActivatedChirho, TestkindCf7OperatorRefusalChirho>
    {
        Err(
            TestkindCf7OperatorRefusalChirho::MigrationActivationRefusedChirho {
                reason_chirho: "migration-activation-not-implemented-chirho".to_owned(),
            },
        )
    }

    /// Begin an attempt and fence the source. DEFAULTS TO A REFUSAL, like its siblings.
    fn migration_begin_source_fence_chirho(
        &self,
        _target_root_chirho: &str,
        _destination_chirho: TenantMigrationDestinationRecordChirho,
        _writer_adoption_chirho: Option<TenantMigrationWriterAdoptionRecordChirho>,
    ) -> std::result::Result<
        TestkindTenantMigrationSourceFencedChirho,
        TestkindCf7OperatorRefusalChirho,
    > {
        Err(
            TestkindCf7OperatorRefusalChirho::MigrationActivationRefusedChirho {
                reason_chirho: "migration-source-fence-not-implemented-chirho".to_owned(),
            },
        )
    }

    fn loss_witness_current_chirho(
        &self,
        _phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    ) -> std::result::Result<
        ResidentTestkindLossWitnessOutcomeChirho,
        TestkindCf7OperatorRefusalChirho,
    > {
        Err(TestkindCf7OperatorRefusalChirho::LossWitnessRefusedChirho {
            refusal_chirho: ResidentTestkindLossWitnessRefusalChirho::TestKindConfigRequiredChirho,
        })
    }

    fn loss_witness_sustained_chirho(
        &self,
        _phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    ) -> std::result::Result<
        ResidentTestkindLossWitnessOutcomeChirho,
        TestkindCf7OperatorRefusalChirho,
    > {
        Err(TestkindCf7OperatorRefusalChirho::LossWitnessRefusedChirho {
            refusal_chirho: ResidentTestkindLossWitnessRefusalChirho::TestKindConfigRequiredChirho,
        })
    }

    fn loss_witness_deposed_sink_chirho(
        &self,
        _phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    ) -> std::result::Result<
        ResidentTestkindLossWitnessOutcomeChirho,
        TestkindCf7OperatorRefusalChirho,
    > {
        Err(TestkindCf7OperatorRefusalChirho::LossWitnessRefusedChirho {
            refusal_chirho: ResidentTestkindLossWitnessRefusalChirho::TestKindConfigRequiredChirho,
        })
    }
}

struct LiveTestkindCf7OperatorAuthorityChirho {
    root_chirho: PathBuf,
    host_chirho: Arc<LedgerHostProjectionReadPortChirho>,
    runtime_chirho: SharedLedgerHostPostgresEffectRuntimeChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TestkindCf7OperatorSocketIdentityChirho {
    device_chirho: u64,
    inode_chirho: u64,
}

impl LiveTestkindCf7OperatorAuthorityChirho {
    fn current_head_chirho(
        &self,
    ) -> std::result::Result<TestkindLedgerHeadBindingChirho, TestkindCf7OperatorRefusalChirho>
    {
        let balances_chirho = self
            .host_chirho
            .read_substrate_balances_chirho()
            .map_err(|_error_chirho| TestkindCf7OperatorRefusalChirho::ExecutionRefusedChirho)?;
        Ok(TestkindLedgerHeadBindingChirho {
            covered_record_count_chirho: balances_chirho.tail_seq_chirho,
            checkpoint_digest_chirho: balances_chirho.tail_line_digest_chirho,
        })
    }
}

impl TestkindCf7OperatorAuthorityChirho for LiveTestkindCf7OperatorAuthorityChirho {
    fn preview_chirho(
        &self,
        app_chirho: &str,
        owner_chirho: &str,
    ) -> std::result::Result<
        CurrentPostgresCompensationPreviewChirho,
        TestkindCf7OperatorRefusalChirho,
    > {
        preview_current_ledger_host_postgres_compensation_chirho(
            &self.runtime_chirho,
            &self.root_chirho,
            app_chirho,
            owner_chirho,
        )
        .map_err(map_preview_refusal_chirho)
    }

    fn execute_chirho(
        &self,
        app_chirho: &str,
        owner_chirho: &str,
        reviewed_preview_chirho: &CurrentPostgresCompensationPreviewChirho,
    ) -> std::result::Result<
        TestkindCompensationExecutionEvidenceChirho,
        TestkindCf7OperatorRefusalChirho,
    > {
        let execution_chirho = execute_reviewed_current_ledger_host_postgres_compensation_chirho(
            &self.runtime_chirho,
            &self.root_chirho,
            app_chirho,
            owner_chirho,
            reviewed_preview_chirho,
        )
        .map_err(map_reviewed_execution_refusal_chirho)?;
        let post_compensation_head_chirho = self.current_head_chirho()?;
        Ok(TestkindCompensationExecutionEvidenceChirho {
            execution_chirho,
            post_compensation_head_chirho,
        })
    }

    fn replay_chirho(
        &self,
        app_chirho: &str,
        owner_chirho: &str,
        expected_execution_chirho: &TestkindCompensationExecutionEvidenceChirho,
    ) -> std::result::Result<
        TestkindCompensationExecutionEvidenceChirho,
        TestkindCf7OperatorRefusalChirho,
    > {
        let before_head_chirho = self.current_head_chirho()?;
        if before_head_chirho != expected_execution_chirho.post_compensation_head_chirho {
            return Err(TestkindCf7OperatorRefusalChirho::ReplayHeadMovedChirho);
        }
        let execution_chirho = replay_completed_current_ledger_host_postgres_compensation_chirho(
            &self.runtime_chirho,
            &self.root_chirho,
            app_chirho,
            owner_chirho,
            &expected_execution_chirho.execution_chirho,
        )
        .map_err(map_reviewed_replay_refusal_chirho)?;
        let after_head_chirho = self.current_head_chirho()?;
        if after_head_chirho != before_head_chirho {
            return Err(TestkindCf7OperatorRefusalChirho::ReplayHeadMovedChirho);
        }
        Ok(TestkindCompensationExecutionEvidenceChirho {
            execution_chirho,
            post_compensation_head_chirho: after_head_chirho,
        })
    }

    fn conservation_read_chirho(
        &self,
        expected_head_chirho: &TestkindLedgerHeadBindingChirho,
    ) -> std::result::Result<LedgerConservationCycleRowChirho, TestkindCf7OperatorRefusalChirho>
    {
        let row_chirho = self
            .host_chirho
            .run_conservation_cycle_once_chirho()
            .map_err(|_error_chirho| TestkindCf7OperatorRefusalChirho::ConservationRefusedChirho)?;
        verify_cf7_conservation_row_chirho(&row_chirho, expected_head_chirho)?;
        Ok(row_chirho)
    }

    fn migration_activate_target_chirho(
        &self,
        target_root_chirho: &str,
    ) -> std::result::Result<TestkindTenantMigrationActivatedChirho, TestkindCf7OperatorRefusalChirho>
    {
        let target_root_chirho = std::path::Path::new(target_root_chirho);
        // The socket passes a PATH and nothing else. Eligibility is computed inside the resident
        // actor, which is the only layer that knows this root's CONFIGURED ledger namespace name —
        // computing it here refused any root whose journal sat under an operator-chosen directory,
        // measured against a real drill root on 2026-08-19.
        let activated_chirho = activate_current_ledger_host_tenant_migration_target_chirho(
            &self.runtime_chirho,
            target_root_chirho,
        )
        .map_err(|refusal_chirho| {
            TestkindCf7OperatorRefusalChirho::MigrationActivationRefusedChirho {
                reason_chirho: format!("resident-refused-chirho:{refusal_chirho:?}"),
            }
        })?;
        Ok(TestkindTenantMigrationActivatedChirho {
            attempt_digest_chirho: activated_chirho.attempt_digest_chirho,
            checkpoint_ref_chirho: activated_chirho.checkpoint_ref_chirho,
            phase_chirho: format!("{:?}", activated_chirho.phase_chirho),
        })
    }

    fn migration_begin_source_fence_chirho(
        &self,
        target_root_chirho: &str,
        destination_chirho: TenantMigrationDestinationRecordChirho,
        writer_adoption_chirho: Option<TenantMigrationWriterAdoptionRecordChirho>,
    ) -> std::result::Result<
        TestkindTenantMigrationSourceFencedChirho,
        TestkindCf7OperatorRefusalChirho,
    > {
        let fenced_chirho = begin_current_ledger_host_tenant_migration_source_fence_chirho(
            &self.runtime_chirho,
            std::path::Path::new(target_root_chirho),
            destination_chirho,
            writer_adoption_chirho,
        )
        .map_err(|refusal_chirho| {
            TestkindCf7OperatorRefusalChirho::MigrationActivationRefusedChirho {
                reason_chirho: format!("resident-refused-chirho:{refusal_chirho:?}"),
            }
        })?;
        Ok(TestkindTenantMigrationSourceFencedChirho {
            attempt_digest_chirho: fenced_chirho.attempt_digest_chirho,
            checkpoint_ref_chirho: fenced_chirho.checkpoint_ref_chirho,
            phase_chirho: format!("{:?}", fenced_chirho.phase_chirho),
            marker_activation_generation_chirho: fenced_chirho.marker_activation_generation_chirho,
        })
    }

    fn loss_witness_current_chirho(
        &self,
        phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    ) -> std::result::Result<
        ResidentTestkindLossWitnessOutcomeChirho,
        TestkindCf7OperatorRefusalChirho,
    > {
        execute_current_ledger_host_testkind_loss_witness_chirho(&self.runtime_chirho, phase_chirho)
            .map_err(
                |refusal_chirho| TestkindCf7OperatorRefusalChirho::LossWitnessRefusedChirho {
                    refusal_chirho,
                },
            )
    }

    fn loss_witness_sustained_chirho(
        &self,
        phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    ) -> std::result::Result<
        ResidentTestkindLossWitnessOutcomeChirho,
        TestkindCf7OperatorRefusalChirho,
    > {
        execute_sustained_ledger_host_testkind_loss_witness_chirho(
            &self.runtime_chirho,
            phase_chirho,
        )
        .map_err(|refusal_chirho| {
            TestkindCf7OperatorRefusalChirho::LossWitnessRefusedChirho { refusal_chirho }
        })
    }

    fn loss_witness_deposed_sink_chirho(
        &self,
        phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    ) -> std::result::Result<
        ResidentTestkindLossWitnessOutcomeChirho,
        TestkindCf7OperatorRefusalChirho,
    > {
        execute_deposed_sink_ledger_host_testkind_loss_witness_chirho(
            &self.runtime_chirho,
            phase_chirho,
        )
        .map_err(|refusal_chirho| {
            TestkindCf7OperatorRefusalChirho::LossWitnessRefusedChirho { refusal_chirho }
        })
    }
}

pub fn testkind_cf7_operator_socket_path_chirho(selected_root_chirho: &Path) -> PathBuf {
    selected_root_chirho
        .join(TESTKIND_CF7_OPERATOR_RUNTIME_DIR_CHIRHO)
        .join(TESTKIND_CF7_OPERATOR_SOCKET_NAME_CHIRHO)
}

pub fn start_testkind_cf7_operator_control_chirho(
    selected_root_chirho: &Path,
    host_chirho: Arc<LedgerHostProjectionReadPortChirho>,
    runtime_chirho: SharedLedgerHostPostgresEffectRuntimeChirho,
    process_stop_chirho: Arc<AtomicBool>,
) -> Result<JoinHandle<Result<()>>> {
    start_testkind_cf7_operator_control_with_authority_chirho(
        selected_root_chirho,
        Arc::new(LiveTestkindCf7OperatorAuthorityChirho {
            root_chirho: selected_root_chirho.to_path_buf(),
            host_chirho,
            runtime_chirho,
        }),
        process_stop_chirho,
    )
}

fn start_testkind_cf7_operator_control_with_authority_chirho(
    selected_root_chirho: &Path,
    authority_chirho: Arc<dyn TestkindCf7OperatorAuthorityChirho>,
    process_stop_chirho: Arc<AtomicBool>,
) -> Result<JoinHandle<Result<()>>> {
    let socket_path_chirho = testkind_cf7_operator_socket_path_chirho(selected_root_chirho);
    prepare_socket_path_chirho(&socket_path_chirho)?;
    let listener_chirho = UnixListener::bind(&socket_path_chirho).with_context(|| {
        format!(
            "bind test-kind CF7 operator socket {}",
            socket_path_chirho.display()
        )
    })?;
    fs::set_permissions(&socket_path_chirho, fs::Permissions::from_mode(0o600))
        .context("set test-kind CF7 operator socket mode 0600")?;
    let socket_identity_chirho = socket_identity_chirho(&socket_path_chirho)?;
    listener_chirho
        .set_nonblocking(true)
        .context("set test-kind CF7 operator socket nonblocking")?;
    let thread_socket_path_chirho = socket_path_chirho.clone();
    std::thread::Builder::new()
        .name("cf7-operator-control-chirho".to_owned())
        .spawn(move || {
            let result_chirho = serve_operator_socket_chirho(
                listener_chirho,
                authority_chirho,
                &process_stop_chirho,
            );
            if result_chirho.is_err() {
                process_stop_chirho.store(true, Ordering::Release);
            }
            remove_owned_socket_if_present_chirho(
                &thread_socket_path_chirho,
                socket_identity_chirho,
            );
            result_chirho
        })
        .map_err(|error_chirho| {
            remove_owned_socket_if_present_chirho(&socket_path_chirho, socket_identity_chirho);
            error_chirho.into()
        })
}

pub fn send_testkind_cf7_operator_request_chirho(
    selected_root_chirho: &Path,
    request_chirho: &TestkindCf7OperatorRequestChirho,
) -> Result<TestkindCf7OperatorResponseChirho> {
    send_testkind_cf7_operator_request_with_timeout_chirho(
        selected_root_chirho,
        request_chirho,
        TESTKIND_CF7_OPERATOR_CLIENT_RESPONSE_TIMEOUT_CHIRHO,
    )
}

fn send_testkind_cf7_operator_request_with_timeout_chirho(
    selected_root_chirho: &Path,
    request_chirho: &TestkindCf7OperatorRequestChirho,
    response_timeout_chirho: Duration,
) -> Result<TestkindCf7OperatorResponseChirho> {
    request_chirho
        .validate_chirho()
        .map_err(|refusal_chirho| anyhow::anyhow!("{refusal_chirho:?}"))
        .context("TestkindCf7OperatorClientRequestValidationRefusedChirho")?;
    let request_bytes_chirho = serde_json::to_vec(request_chirho)
        .context("TestkindCf7OperatorClientRequestEncodingRefusedChirho")?;
    let mut stream_chirho = UnixStream::connect(testkind_cf7_operator_socket_path_chirho(
        selected_root_chirho,
    ))
    .context("TestkindCf7OperatorClientSocketConnectRefusedChirho")?;
    stream_chirho
        .set_read_timeout(Some(response_timeout_chirho))
        .context("TestkindCf7OperatorClientReadTimeoutSetupRefusedChirho")?;
    stream_chirho
        .write_all(&request_bytes_chirho)
        .and_then(|()| stream_chirho.write_all(b"\n"))
        .context("TestkindCf7OperatorClientRequestWriteRefusedChirho")?;
    stream_chirho
        .shutdown(std::net::Shutdown::Write)
        .context("TestkindCf7OperatorClientRequestFinishRefusedChirho")?;
    let mut response_bytes_chirho = Vec::new();
    stream_chirho
        .take(MAX_TESTKIND_CF7_OPERATOR_WIRE_BYTES_CHIRHO + 2)
        .read_to_end(&mut response_bytes_chirho)
        .context("TestkindCf7OperatorClientResponseReadRefusedChirho")?;
    let response_wire_chirho = canonical_line_payload_chirho(&response_bytes_chirho)
        .map_err(|refusal_chirho| anyhow::anyhow!("{refusal_chirho:?}"))
        .context("TestkindCf7OperatorClientResponseShapeRefusedChirho")?;
    let response_chirho: TestkindCf7OperatorResponseChirho =
        serde_json::from_slice(response_wire_chirho)
            .context("TestkindCf7OperatorClientResponseParseRefusedChirho")?;
    let canonical_response_chirho = serde_json::to_vec(&response_chirho)
        .context("TestkindCf7OperatorClientResponseEncodingRefusedChirho")?;
    if response_chirho.schema_chirho != TESTKIND_CF7_OPERATOR_RESPONSE_SCHEMA_CHIRHO
        || canonical_response_chirho != response_wire_chirho
    {
        bail!("TestkindCf7OperatorClientResponseCanonicalRefusedChirho");
    }
    Ok(response_chirho)
}

pub fn verify_cf7_conservation_row_chirho(
    row_chirho: &LedgerConservationCycleRowChirho,
    expected_head_chirho: &TestkindLedgerHeadBindingChirho,
) -> std::result::Result<(), TestkindCf7OperatorRefusalChirho> {
    let LedgerConservationCycleOutcomeChirho::GreenChirho {
        head_chirho,
        money_group_kind_scopes_checked_chirho,
        domain_kind_rollups_checked_chirho,
        global_supplies_checked_chirho,
        work_items_checked_chirho,
    } = &row_chirho.outcome_chirho
    else {
        return Err(TestkindCf7OperatorRefusalChirho::ConservationNotGreenChirho);
    };
    if *money_group_kind_scopes_checked_chirho == 0
        || *domain_kind_rollups_checked_chirho == 0
        || *global_supplies_checked_chirho == 0
        || *work_items_checked_chirho == 0
    {
        return Err(TestkindCf7OperatorRefusalChirho::ConservationEmptyChirho);
    }
    if head_chirho.covered_record_count_chirho != expected_head_chirho.covered_record_count_chirho
        || head_chirho.checkpoint_digest_chirho != expected_head_chirho.checkpoint_digest_chirho
    {
        return Err(TestkindCf7OperatorRefusalChirho::ConservationHeadMismatchChirho);
    }
    Ok(())
}

fn prepare_socket_path_chirho(socket_path_chirho: &Path) -> Result<()> {
    let runtime_dir_chirho = socket_path_chirho
        .parent()
        .ok_or_else(|| anyhow::anyhow!("test-kind CF7 operator socket has no parent"))?;
    match fs::symlink_metadata(runtime_dir_chirho) {
        Ok(metadata_chirho) if metadata_chirho.file_type().is_dir() => {}
        Ok(_) => bail!("TestkindCf7OperatorRuntimeDirectoryRefusedChirho"),
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(runtime_dir_chirho)
                .context("create test-kind CF7 operator runtime directory")?;
        }
        Err(error_chirho) => return Err(error_chirho.into()),
    }
    fs::set_permissions(runtime_dir_chirho, fs::Permissions::from_mode(0o700))
        .context("set test-kind CF7 operator runtime directory mode 0700")?;
    match fs::symlink_metadata(socket_path_chirho) {
        Ok(metadata_chirho) if metadata_chirho.file_type().is_socket() => {
            match UnixStream::connect(socket_path_chirho) {
                Ok(_active_stream_chirho) => {
                    bail!("TestkindCf7OperatorSocketAlreadyActiveChirho")
                }
                Err(error_chirho)
                    if matches!(
                        error_chirho.kind(),
                        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                    ) =>
                {
                    fs::remove_file(socket_path_chirho)
                        .context("remove stale test-kind CF7 operator socket")?;
                }
                Err(error_chirho) => {
                    return Err(error_chirho)
                        .context("probe existing test-kind CF7 operator socket")
                }
            }
        }
        Ok(_) => bail!("TestkindCf7OperatorPreexistingPathRefusedChirho"),
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => {}
        Err(error_chirho) => return Err(error_chirho.into()),
    }
    Ok(())
}

fn serve_operator_socket_chirho(
    listener_chirho: UnixListener,
    authority_chirho: Arc<dyn TestkindCf7OperatorAuthorityChirho>,
    process_stop_chirho: &AtomicBool,
) -> Result<()> {
    while !process_stop_chirho.load(Ordering::Acquire) {
        match listener_chirho.accept() {
            Ok((stream_chirho, _address_chirho)) => {
                handle_operator_connection_chirho(stream_chirho, authority_chirho.as_ref());
            }
            Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error_chirho) => return Err(error_chirho.into()),
        }
    }
    Ok(())
}

fn handle_operator_connection_chirho(
    mut stream_chirho: UnixStream,
    authority_chirho: &dyn TestkindCf7OperatorAuthorityChirho,
) {
    // An accepted stream inherits the listener's non-blocking flag on macOS (Linux does not), so a read on it returned at
    // once when the client had not written yet: the server refused and closed, and a client slowed between connect and
    // its write (as under load) met EINVAL on its next setsockopt. Blocking, the read timeout below governs. A stream
    // that cannot be made blocking is closed unanswered rather than read wrongly.
    if stream_chirho.set_nonblocking(false).is_err() {
        return;
    }
    let _timeout_chirho = stream_chirho.set_read_timeout(Some(Duration::from_secs(2)));
    let mut request_bytes_chirho = Vec::new();
    let response_chirho = match (&mut stream_chirho)
        .take(MAX_TESTKIND_CF7_OPERATOR_WIRE_BYTES_CHIRHO + 2)
        .read_to_end(&mut request_bytes_chirho)
    {
        Ok(_) => dispatch_wire_request_chirho(&request_bytes_chirho, authority_chirho),
        Err(_error_chirho) => TestkindCf7OperatorResponseChirho::refused_chirho(
            TestkindCf7OperatorRefusalChirho::NoncanonicalRequestChirho,
        ),
    };
    if let Ok(mut response_bytes_chirho) = serde_json::to_vec(&response_chirho) {
        response_bytes_chirho.push(b'\n');
        let _write_chirho = stream_chirho.write_all(&response_bytes_chirho);
    }
}

fn dispatch_wire_request_chirho(
    request_bytes_chirho: &[u8],
    authority_chirho: &dyn TestkindCf7OperatorAuthorityChirho,
) -> TestkindCf7OperatorResponseChirho {
    let request_wire_chirho = match canonical_line_payload_chirho(request_bytes_chirho) {
        Ok(request_wire_chirho) => request_wire_chirho,
        Err(refusal_chirho) => {
            return TestkindCf7OperatorResponseChirho::refused_chirho(refusal_chirho)
        }
    };
    let request_chirho: TestkindCf7OperatorRequestChirho =
        match serde_json::from_slice(request_wire_chirho) {
            Ok(request_chirho) => request_chirho,
            Err(_error_chirho) => {
                return TestkindCf7OperatorResponseChirho::refused_chirho(
                    TestkindCf7OperatorRefusalChirho::NoncanonicalRequestChirho,
                )
            }
        };
    if serde_json::to_vec(&request_chirho).ok().as_deref() != Some(request_wire_chirho) {
        return TestkindCf7OperatorResponseChirho::refused_chirho(
            TestkindCf7OperatorRefusalChirho::NoncanonicalRequestChirho,
        );
    }
    if let Err(refusal_chirho) = request_chirho.validate_chirho() {
        return TestkindCf7OperatorResponseChirho::refused_chirho(refusal_chirho);
    }
    let outcome_chirho =
        match request_chirho.operation_chirho {
            TestkindCf7OperatorOperationChirho::PreviewChirho {
                app_chirho,
                owner_chirho,
            } => authority_chirho
                .preview_chirho(&app_chirho, &owner_chirho)
                .map(
                    |preview_chirho| TestkindCf7OperatorOutcomeChirho::PreviewChirho {
                        preview_chirho,
                    },
                ),
            TestkindCf7OperatorOperationChirho::ExecuteChirho {
                app_chirho,
                owner_chirho,
                reviewed_preview_chirho,
            } => authority_chirho
                .execute_chirho(&app_chirho, &owner_chirho, &reviewed_preview_chirho)
                .map(
                    |evidence_chirho| TestkindCf7OperatorOutcomeChirho::ExecutedChirho {
                        evidence_chirho,
                    },
                ),
            TestkindCf7OperatorOperationChirho::ReplayChirho {
                app_chirho,
                owner_chirho,
                expected_execution_chirho,
            } => authority_chirho
                .replay_chirho(&app_chirho, &owner_chirho, &expected_execution_chirho)
                .map(
                    |evidence_chirho| TestkindCf7OperatorOutcomeChirho::ReplayedChirho {
                        evidence_chirho,
                    },
                ),
            TestkindCf7OperatorOperationChirho::ConservationReadChirho {
                expected_head_chirho,
            } => authority_chirho
                .conservation_read_chirho(&expected_head_chirho)
                .map(
                    |row_chirho| TestkindCf7OperatorOutcomeChirho::ConservationGreenChirho {
                        row_chirho,
                    },
                ),
            TestkindCf7OperatorOperationChirho::MigrationActivateTargetChirho {
                target_root_chirho,
            } => authority_chirho
                .migration_activate_target_chirho(&target_root_chirho)
                .map(|activated_chirho| {
                    TestkindCf7OperatorOutcomeChirho::MigrationActivatedChirho { activated_chirho }
                }),
            TestkindCf7OperatorOperationChirho::MigrationBeginSourceFenceChirho {
                target_root_chirho,
                destination_chirho,
                writer_adoption_chirho,
            } => authority_chirho
                .migration_begin_source_fence_chirho(
                    &target_root_chirho,
                    *destination_chirho,
                    writer_adoption_chirho.map(|record_chirho| *record_chirho),
                )
                .map(|fenced_chirho| {
                    TestkindCf7OperatorOutcomeChirho::MigrationSourceFencedChirho { fenced_chirho }
                }),
            TestkindCf7OperatorOperationChirho::LossWitnessCurrentChirho { phase_chirho } => {
                authority_chirho
                    .loss_witness_current_chirho(phase_chirho)
                    .map(
                        |witness_chirho| TestkindCf7OperatorOutcomeChirho::LossWitnessChirho {
                            witness_chirho,
                        },
                    )
            }
            TestkindCf7OperatorOperationChirho::LossWitnessSustainedChirho { phase_chirho } => {
                authority_chirho
                    .loss_witness_sustained_chirho(phase_chirho)
                    .map(
                        |witness_chirho| TestkindCf7OperatorOutcomeChirho::LossWitnessChirho {
                            witness_chirho,
                        },
                    )
            }
            TestkindCf7OperatorOperationChirho::LossWitnessDeposedSinkChirho { phase_chirho } => {
                authority_chirho
                    .loss_witness_deposed_sink_chirho(phase_chirho)
                    .map(
                        |witness_chirho| TestkindCf7OperatorOutcomeChirho::LossWitnessChirho {
                            witness_chirho,
                        },
                    )
            }
        };
    match outcome_chirho {
        Ok(outcome_chirho) => TestkindCf7OperatorResponseChirho::outcome_chirho(outcome_chirho),
        Err(refusal_chirho) => TestkindCf7OperatorResponseChirho::refused_chirho(refusal_chirho),
    }
}

fn canonical_line_payload_chirho(
    bytes_chirho: &[u8],
) -> std::result::Result<&[u8], TestkindCf7OperatorRefusalChirho> {
    if bytes_chirho.len() as u64 > MAX_TESTKIND_CF7_OPERATOR_WIRE_BYTES_CHIRHO + 1 {
        return Err(TestkindCf7OperatorRefusalChirho::RequestTooLargeChirho);
    }
    let Some(payload_chirho) = bytes_chirho.strip_suffix(b"\n") else {
        return Err(TestkindCf7OperatorRefusalChirho::NoncanonicalRequestChirho);
    };
    if payload_chirho.is_empty() || payload_chirho.contains(&b'\n') {
        return Err(TestkindCf7OperatorRefusalChirho::NoncanonicalRequestChirho);
    }
    Ok(payload_chirho)
}

/// Shape-only hygiene on an operator-supplied target root path.
///
/// This is NOT the authorization. The path is opened as a verified tenant root, and the cut opener
/// re-checks that the ledger namespace lies inside that verified root, refusing
/// `LedgerNamespaceOutsideRootChirho`. This only keeps obviously malformed input off an authority
/// surface: absolute, bounded, and free of interior NULs.
fn validate_target_root_path_chirho(
    path_chirho: &str,
) -> std::result::Result<(), TestkindCf7OperatorRefusalChirho> {
    if path_chirho.is_empty()
        || path_chirho.len() > MAX_TESTKIND_TARGET_ROOT_PATH_BYTES_CHIRHO
        || !path_chirho.starts_with('/')
        || path_chirho.contains('\0')
    {
        return Err(TestkindCf7OperatorRefusalChirho::InvalidTokenChirho);
    }
    Ok(())
}

fn validate_token_chirho(
    token_chirho: &str,
) -> std::result::Result<(), TestkindCf7OperatorRefusalChirho> {
    if token_chirho.is_empty()
        || token_chirho.len() > MAX_TESTKIND_CF7_OPERATOR_TOKEN_BYTES_CHIRHO
        || token_chirho
            .chars()
            .any(|char_chirho| char_chirho.is_control() || char_chirho.is_whitespace())
    {
        return Err(TestkindCf7OperatorRefusalChirho::InvalidTokenChirho);
    }
    Ok(())
}

fn validate_head_chirho(
    head_chirho: &TestkindLedgerHeadBindingChirho,
) -> std::result::Result<(), TestkindCf7OperatorRefusalChirho> {
    if head_chirho.covered_record_count_chirho == 0
        || head_chirho.checkpoint_digest_chirho.len() != 64
        || !head_chirho
            .checkpoint_digest_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
    {
        return Err(TestkindCf7OperatorRefusalChirho::InvalidHeadChirho);
    }
    Ok(())
}

fn socket_identity_chirho(
    socket_path_chirho: &Path,
) -> Result<TestkindCf7OperatorSocketIdentityChirho> {
    let metadata_chirho = fs::symlink_metadata(socket_path_chirho)
        .context("inspect test-kind CF7 operator socket identity")?;
    if !metadata_chirho.file_type().is_socket() {
        bail!("TestkindCf7OperatorSocketIdentityRefusedChirho");
    }
    Ok(TestkindCf7OperatorSocketIdentityChirho {
        device_chirho: metadata_chirho.dev(),
        inode_chirho: metadata_chirho.ino(),
    })
}

fn remove_owned_socket_if_present_chirho(
    socket_path_chirho: &Path,
    expected_identity_chirho: TestkindCf7OperatorSocketIdentityChirho,
) {
    if socket_identity_chirho(socket_path_chirho).ok() == Some(expected_identity_chirho) {
        let _remove_chirho = fs::remove_file(socket_path_chirho);
    }
}

#[cfg(test)]
#[path = "operator_control_chirho/tests_chirho.rs"]
mod tests_chirho;
