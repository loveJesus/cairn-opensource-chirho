// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Open-only LocalPhaseB Descriptor-D adapter for the configured ledger host.
//!
//! Workflow: `spec-chirho/workflows-chirho/projection-chirho/cf7-read-composition-design-chirho.md`.
//! The adapter owns the synchronous PostgreSQL client and one process-resident neutral journal
//! handle. Mutations cross that handle into the actor-owned elected authority; projection re-feed
//! opens only a verified read view. A committed terminal remains authoritative if re-feed fails;
//! the older signed projection head then classifies non-Fresh until a retry heals it.

use super::LedgerHostProjectionReadPortChirho;
use anyhow::Result;
use cairn_chirho::effect_chirho::postgres_reversible_chirho::{
    mint_verified_current_undo_plan_authority_chirho,
    parse_canonical_postgres_effect_terminal_disposition_chirho,
    verify_local_postgres_effect_adapter_custody_chirho, AppPriceBookUserPaysPolicyChirho,
    CurrentPostgresCompensationExecutionChirho, CurrentPostgresCompensationPreviewChirho,
    CurrentPostgresCompensationPreviewVerdictChirho, EffectTerminalDispositionChirho,
    LocalPostgresEffectCompositionChirho, PostgresReversibleExecutionChirho,
    PostgresReversibleRuntimePortChirho,
};
use cairn_config_chirho::config_chirho::{
    LedgerHostConfigChirho, LedgerHostPostgresEffectPostureChirho,
};
use cairn_ledger_composition_chirho::LedgerReadCompositionChirho;
use cairn_ledger_host_chirho::{
    open_resident_effect_journal_handle_chirho, PlatformPolicyMintAuthorityChirho,
    ResidentEffectJournalHandleChirho, ResidentTenantMigrationOperationRefusalChirho,
    ResidentTenantMigrationSourceFenceStatusChirho,
    ResidentTenantMigrationTargetActivatedStatusChirho, ResidentTestkindLossWitnessOutcomeChirho,
    ResidentTestkindLossWitnessPhaseChirho, ResidentTestkindLossWitnessRefusalChirho,
    TenantMigrationDestinationRecordChirho, TenantMigrationWriterAdoptionRecordChirho,
};
use cairn_ledger_log_chirho::journal_chirho::JournalPortsChirho;
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, DigestChirho};
use cairn_ledger_read_model_chirho::feeder_chirho::ProjectionSourceChirho;
use cairn_ledger_read_model_chirho::registry_chirho::load_verified_projection_registry_chirho;
use cairn_ledger_read_model_chirho::{
    account_net_projection_fold_ref_chirho, AccountNetProjectionFoldChirho,
    ProjectionCostClassChirho,
};
use cairn_postgres_effect_chirho::ports_chirho::ReversiblePostgresDatabasePortChirho;
use cairn_postgres_effect_chirho::PostgresDatabaseChirho;
use cairn_secret_chirho::secret_chirho::{resolve_secret_ref_chirho, secret_ref_chirho};
use postgres::config::Host;
use postgres::{Config, NoTls};
use std::error::Error;
use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[cfg(test)]
#[path = "postgres_effect_chirho/connection_tests_chirho.rs"]
mod connection_tests_chirho;
#[cfg(test)]
#[path = "postgres_effect_chirho/lifecycle_tests_chirho.rs"]
mod lifecycle_tests_chirho;

trait LedgerHostPostgresEffectPortChirho: Send {
    fn runtime_port_chirho(&mut self) -> &mut dyn PostgresReversibleRuntimePortChirho;

    fn preview_current_compensation_chirho(
        &mut self,
        root_chirho: &Path,
        app_chirho: &str,
        owner_chirho: &str,
    ) -> Result<CurrentPostgresCompensationPreviewChirho>;

    fn execute_current_compensation_chirho(
        &mut self,
        root_chirho: &Path,
        app_chirho: &str,
        owner_chirho: &str,
    ) -> Result<CurrentPostgresCompensationExecutionChirho>;

    fn execute_current_testkind_loss_witness_chirho(
        &mut self,
        phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    ) -> std::result::Result<
        ResidentTestkindLossWitnessOutcomeChirho,
        ResidentTestkindLossWitnessRefusalChirho,
    >;

    /// Activate a tenant-root migration target through the LIVE resident actor.
    ///
    /// It must be the live actor: the source-fence witness is in-memory and the append barrier is
    /// actor state, so a second process opening the store would be activating without the witness
    /// the migration contract requires.
    fn activate_current_tenant_migration_target_chirho(
        &mut self,
        target_root_chirho: &Path,
    ) -> std::result::Result<
        ResidentTenantMigrationTargetActivatedStatusChirho,
        ResidentTenantMigrationOperationRefusalChirho,
    >;

    /// Begin a tenant-root migration attempt and fence the source, through the LIVE resident actor.
    ///
    /// Live for the same reason activation is: the fence it installs is actor state. It carries the
    /// externally signed destination authorization, which is what separates "an operator named a
    /// path" from "this node was authorized to move onto that root".
    fn begin_current_tenant_migration_source_fence_chirho(
        &mut self,
        target_root_chirho: &Path,
        destination_chirho: TenantMigrationDestinationRecordChirho,
        writer_adoption_chirho: Option<TenantMigrationWriterAdoptionRecordChirho>,
    ) -> std::result::Result<
        ResidentTenantMigrationSourceFenceStatusChirho,
        ResidentTenantMigrationOperationRefusalChirho,
    >;

    fn execute_sustained_testkind_loss_witness_chirho(
        &mut self,
        phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    ) -> std::result::Result<
        ResidentTestkindLossWitnessOutcomeChirho,
        ResidentTestkindLossWitnessRefusalChirho,
    >;

    fn execute_deposed_sink_testkind_loss_witness_chirho(
        &mut self,
        phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    ) -> std::result::Result<
        ResidentTestkindLossWitnessOutcomeChirho,
        ResidentTestkindLossWitnessRefusalChirho,
    >;
}

#[derive(Clone)]
pub struct SharedLedgerHostPostgresEffectRuntimeChirho {
    inner_chirho: Arc<Mutex<Box<dyn LedgerHostPostgresEffectPortChirho>>>,
}

impl SharedLedgerHostPostgresEffectRuntimeChirho {
    fn new_chirho(runtime_chirho: LedgerHostPostgresEffectRuntimeChirho) -> Self {
        Self {
            inner_chirho: Arc::new(Mutex::new(Box::new(runtime_chirho))),
        }
    }

    pub(crate) fn with_runtime_chirho<OutputChirho>(
        &self,
        call_chirho: impl FnOnce(&mut dyn PostgresReversibleRuntimePortChirho) -> Result<OutputChirho>,
    ) -> Result<OutputChirho> {
        let mut runtime_chirho = self.inner_chirho.lock().map_err(|_error_chirho| {
            LedgerHostPostgresEffectRefusalChirho::ProviderLockUnavailableChirho
        })?;
        call_chirho(runtime_chirho.runtime_port_chirho())
    }

    fn with_host_port_chirho<OutputChirho>(
        &self,
        call_chirho: impl FnOnce(&mut dyn LedgerHostPostgresEffectPortChirho) -> Result<OutputChirho>,
    ) -> Result<OutputChirho> {
        let mut runtime_chirho = self.inner_chirho.lock().map_err(|_error_chirho| {
            LedgerHostPostgresEffectRefusalChirho::ProviderLockUnavailableChirho
        })?;
        call_chirho(runtime_chirho.as_mut())
    }

    fn with_tenant_migration_activation_port_chirho<OutputChirho>(
        &self,
        call_chirho: impl FnOnce(
            &mut dyn LedgerHostPostgresEffectPortChirho,
        ) -> std::result::Result<
            OutputChirho,
            ResidentTenantMigrationOperationRefusalChirho,
        >,
    ) -> std::result::Result<OutputChirho, ResidentTenantMigrationOperationRefusalChirho> {
        let mut runtime_chirho = self.inner_chirho.lock().map_err(|_error_chirho| {
            ResidentTenantMigrationOperationRefusalChirho::ActorUnavailableChirho
        })?;
        call_chirho(runtime_chirho.as_mut())
    }

    fn with_testkind_loss_witness_port_chirho<OutputChirho>(
        &self,
        call_chirho: impl FnOnce(
            &mut dyn LedgerHostPostgresEffectPortChirho,
        ) -> std::result::Result<
            OutputChirho,
            ResidentTestkindLossWitnessRefusalChirho,
        >,
    ) -> std::result::Result<OutputChirho, ResidentTestkindLossWitnessRefusalChirho> {
        let mut runtime_chirho = self.inner_chirho.lock().map_err(|_error_chirho| {
            ResidentTestkindLossWitnessRefusalChirho::ActorUnavailableChirho
        })?;
        call_chirho(runtime_chirho.as_mut())
    }

    #[cfg(test)]
    pub(crate) fn from_runtime_for_test_chirho(
        runtime_chirho: Box<dyn PostgresReversibleRuntimePortChirho + Send>,
    ) -> Self {
        Self {
            inner_chirho: Arc::new(Mutex::new(Box::new(RuntimeOnlyPostgresEffectPortChirho {
                runtime_chirho,
            }))),
        }
    }
}

#[cfg(test)]
struct RuntimeOnlyPostgresEffectPortChirho {
    runtime_chirho: Box<dyn PostgresReversibleRuntimePortChirho + Send>,
}

#[cfg(test)]
impl LedgerHostPostgresEffectPortChirho for RuntimeOnlyPostgresEffectPortChirho {
    fn runtime_port_chirho(&mut self) -> &mut dyn PostgresReversibleRuntimePortChirho {
        self.runtime_chirho.as_mut()
    }

    fn preview_current_compensation_chirho(
        &mut self,
        _root_chirho: &Path,
        _app_chirho: &str,
        _owner_chirho: &str,
    ) -> Result<CurrentPostgresCompensationPreviewChirho> {
        Err(LedgerHostPostgresEffectRefusalChirho::ProviderLockUnavailableChirho.into())
    }

    fn execute_current_compensation_chirho(
        &mut self,
        _root_chirho: &Path,
        _app_chirho: &str,
        _owner_chirho: &str,
    ) -> Result<CurrentPostgresCompensationExecutionChirho> {
        Err(LedgerHostPostgresEffectRefusalChirho::ProviderLockUnavailableChirho.into())
    }

    fn execute_current_testkind_loss_witness_chirho(
        &mut self,
        _phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    ) -> std::result::Result<
        ResidentTestkindLossWitnessOutcomeChirho,
        ResidentTestkindLossWitnessRefusalChirho,
    > {
        Err(ResidentTestkindLossWitnessRefusalChirho::TestKindConfigRequiredChirho)
    }

    fn activate_current_tenant_migration_target_chirho(
        &mut self,
        _target_root_chirho: &Path,
    ) -> std::result::Result<
        ResidentTenantMigrationTargetActivatedStatusChirho,
        ResidentTenantMigrationOperationRefusalChirho,
    > {
        Err(ResidentTenantMigrationOperationRefusalChirho::ActorUnavailableChirho)
    }

    fn begin_current_tenant_migration_source_fence_chirho(
        &mut self,
        _target_root_chirho: &Path,
        _destination_chirho: TenantMigrationDestinationRecordChirho,
        _writer_adoption_chirho: Option<TenantMigrationWriterAdoptionRecordChirho>,
    ) -> std::result::Result<
        ResidentTenantMigrationSourceFenceStatusChirho,
        ResidentTenantMigrationOperationRefusalChirho,
    > {
        Err(ResidentTenantMigrationOperationRefusalChirho::ActorUnavailableChirho)
    }

    fn execute_sustained_testkind_loss_witness_chirho(
        &mut self,
        _phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    ) -> std::result::Result<
        ResidentTestkindLossWitnessOutcomeChirho,
        ResidentTestkindLossWitnessRefusalChirho,
    > {
        Err(ResidentTestkindLossWitnessRefusalChirho::TestKindConfigRequiredChirho)
    }

    fn execute_deposed_sink_testkind_loss_witness_chirho(
        &mut self,
        _phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    ) -> std::result::Result<
        ResidentTestkindLossWitnessOutcomeChirho,
        ResidentTestkindLossWitnessRefusalChirho,
    > {
        Err(ResidentTestkindLossWitnessRefusalChirho::TestKindConfigRequiredChirho)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LedgerHostPostgresEffectRefusalChirho {
    PostgresEffectConfigUnavailableChirho,
    ConnectionSecretUnavailableChirho,
    ConnectionOutsideLocalPhaseBChirho,
    ConnectionUnavailableChirho,
    DatabaseSchemaUnavailableChirho,
    AdapterCustodyUnavailableChirho,
    BillingKindUnavailableChirho,
    ProjectionRouteUnavailableChirho,
    ProjectionFeedUnavailableChirho,
    ProviderLockUnavailableChirho,
    BlockingDispatchUnavailableChirho,
    ForeignRootChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReviewedCurrentPostgresCompensationRefusalChirho {
    PreviewChangedChirho,
    PreviewNotExecutableChirho,
    ReplayNotCompletedChirho,
    ReplayExecutionChangedChirho,
}

impl fmt::Display for ReviewedCurrentPostgresCompensationRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(match self {
            Self::PreviewChangedChirho => "ReviewedCompensationPreviewChangedChirho",
            Self::PreviewNotExecutableChirho => "ReviewedCompensationPreviewNotExecutableChirho",
            Self::ReplayNotCompletedChirho => "ReviewedCompensationReplayNotCompletedChirho",
            Self::ReplayExecutionChangedChirho => "ReviewedCompensationReplayChangedChirho",
        })
    }
}

impl Error for ReviewedCurrentPostgresCompensationRefusalChirho {}

impl fmt::Display for LedgerHostPostgresEffectRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(match self {
            Self::PostgresEffectConfigUnavailableChirho => {
                "configured LocalPhaseB PostgreSQL effect block is unavailable"
            }
            Self::ConnectionSecretUnavailableChirho => {
                "configured LocalPhaseB PostgreSQL connection custody is unavailable"
            }
            Self::ConnectionOutsideLocalPhaseBChirho => {
                "configured LocalPhaseB PostgreSQL connection is not loopback-only"
            }
            Self::ConnectionUnavailableChirho => {
                "configured LocalPhaseB PostgreSQL connection is unavailable"
            }
            Self::DatabaseSchemaUnavailableChirho => {
                "configured LocalPhaseB PostgreSQL schema is unavailable"
            }
            Self::AdapterCustodyUnavailableChirho => {
                "configured Descriptor-D adapter custody is unavailable"
            }
            Self::BillingKindUnavailableChirho => {
                "configured Descriptor-D billing kind lacks a current settlement policy"
            }
            Self::ProjectionRouteUnavailableChirho => {
                "configured Descriptor-D projection route is not a current account-net standing-write route"
            }
            Self::ProjectionFeedUnavailableChirho => {
                "committed Descriptor-D terminal could not refresh every configured projection route"
            }
            Self::ProviderLockUnavailableChirho => {
                "configured Descriptor-D provider lock is unavailable"
            }
            Self::BlockingDispatchUnavailableChirho => {
                "configured Descriptor-D blocking dispatch is unavailable"
            }
            Self::ForeignRootChirho => {
                "configured Descriptor-D host cannot execute for another Cairn root"
            }
        })
    }
}

impl Error for LedgerHostPostgresEffectRefusalChirho {}

struct LedgerHostPostgresEffectRuntimeChirho {
    root_chirho: PathBuf,
    host_chirho: Arc<LedgerHostProjectionReadPortChirho>,
    journal_chirho: ResidentEffectJournalHandleChirho,
    database_chirho: PostgresDatabaseChirho,
    billing_kind_chirho: AssetKindIdChirho,
}

/// Open the only LocalPhaseB provider lane. Secret resolution, database schema verification,
/// adapter custody, the current settlement policy, and every configured projection route are
/// checked before the shared runtime can be passed to serve.
pub fn open_shared_ledger_host_postgres_effect_runtime_chirho(
    root_chirho: &Path,
    config_path_chirho: &Path,
    host_chirho: Arc<LedgerHostProjectionReadPortChirho>,
    ledger_config_chirho: &LedgerHostConfigChirho,
) -> Result<SharedLedgerHostPostgresEffectRuntimeChirho> {
    let (database_chirho, billing_kind_chirho) =
        prepare_ledger_host_postgres_effect_runtime_chirho(
            root_chirho,
            &host_chirho,
            ledger_config_chirho,
        )?;
    let journal_chirho = open_resident_effect_journal_handle_chirho(
        root_chirho,
        config_path_chirho,
        ledger_config_chirho,
        None,
    )?;
    Ok(
        shared_ledger_host_postgres_effect_runtime_from_parts_chirho(
            root_chirho,
            host_chirho,
            journal_chirho,
            database_chirho,
            billing_kind_chirho,
        ),
    )
}

/// Compose the served provider around an already-open resident actor.
///
/// The geo process uses this only after the actor has joined its exact externally ticked elector.
/// Root and full typed config equality are rechecked before database or projection authority can be
/// paired with that actor.
pub fn open_shared_ledger_host_postgres_effect_runtime_with_resident_journal_chirho(
    root_chirho: &Path,
    host_chirho: Arc<LedgerHostProjectionReadPortChirho>,
    ledger_config_chirho: &LedgerHostConfigChirho,
    journal_chirho: ResidentEffectJournalHandleChirho,
) -> Result<SharedLedgerHostPostgresEffectRuntimeChirho> {
    journal_chirho.verify_runtime_binding_chirho(root_chirho, ledger_config_chirho)?;
    let (database_chirho, billing_kind_chirho) =
        prepare_ledger_host_postgres_effect_runtime_chirho(
            root_chirho,
            &host_chirho,
            ledger_config_chirho,
        )?;
    Ok(
        shared_ledger_host_postgres_effect_runtime_from_parts_chirho(
            root_chirho,
            host_chirho,
            journal_chirho,
            database_chirho,
            billing_kind_chirho,
        ),
    )
}

fn prepare_ledger_host_postgres_effect_runtime_chirho(
    root_chirho: &Path,
    host_chirho: &LedgerHostProjectionReadPortChirho,
    ledger_config_chirho: &LedgerHostConfigChirho,
) -> Result<(PostgresDatabaseChirho, AssetKindIdChirho)> {
    ledger_config_chirho.validate_chirho()?;
    let postgres_config_chirho = ledger_config_chirho
        .postgres_effect_chirho
        .as_ref()
        .ok_or(LedgerHostPostgresEffectRefusalChirho::PostgresEffectConfigUnavailableChirho)?;
    match postgres_config_chirho.posture_chirho {
        LedgerHostPostgresEffectPostureChirho::LocalPhaseBChirho => {}
    }
    let billing_kind_chirho = AssetKindIdChirho(postgres_config_chirho.billing_kind_chirho.clone());
    current_feed_routes_for_host_chirho(host_chirho)?;
    verify_current_billing_kind_for_host_chirho(host_chirho, &billing_kind_chirho)?;
    verify_local_postgres_effect_adapter_custody_chirho(root_chirho).map_err(|_error_chirho| {
        LedgerHostPostgresEffectRefusalChirho::AdapterCustodyUnavailableChirho
    })?;
    let database_chirho = connect_local_phase_b_database_chirho(
        root_chirho,
        &postgres_config_chirho.connection_secret_chirho,
    )?;
    Ok((database_chirho, billing_kind_chirho))
}

fn shared_ledger_host_postgres_effect_runtime_from_parts_chirho(
    root_chirho: &Path,
    host_chirho: Arc<LedgerHostProjectionReadPortChirho>,
    journal_chirho: ResidentEffectJournalHandleChirho,
    database_chirho: PostgresDatabaseChirho,
    billing_kind_chirho: AssetKindIdChirho,
) -> SharedLedgerHostPostgresEffectRuntimeChirho {
    let runtime_chirho = LedgerHostPostgresEffectRuntimeChirho {
        root_chirho: root_chirho.to_path_buf(),
        host_chirho,
        journal_chirho,
        database_chirho,
        billing_kind_chirho,
    };
    SharedLedgerHostPostgresEffectRuntimeChirho::new_chirho(runtime_chirho)
}

/// Read-only provider preflight: run exactly the checks the served effect runtime performs before
/// it composes, then drop everything they opened.
///
/// This is the same `prepare_…` the served composition calls, so it cannot drift from serving: it
/// covers config validation, the LocalPhaseB posture, the projection feed routes, the specific
/// billing kind and its settlement owner, adapter custody, and connection-secret resolution plus
/// connect. A caller therefore learns which of those refuses WITHOUT spending a serve startup.
///
/// **It deliberately does not open a resident effect journal, and that is the point of having it.**
/// Opening one is the money-authority door; a preflight has no business taking write authority to
/// answer a read question. That omission also makes the preflight usable by a synthetic drill,
/// because the production door carries the test-kind fence
/// (`TestKindMarkedLedgerHostConfigRefusedChirho`) which refuses a test-kind-marked config by
/// design. Measured on hosts 2026-08-16: a preflight routed through the full production opener
/// refused every candidate at that fence, including the initial owner, which says nothing about the
/// candidate's provider substrate. Note what this means for scope: a green here is a statement
/// about the effect-runtime preconditions only, never about resident-actor authority.
pub fn preflight_ledger_host_postgres_effect_runtime_chirho(
    root_chirho: &Path,
    host_chirho: &LedgerHostProjectionReadPortChirho,
    ledger_config_chirho: &LedgerHostConfigChirho,
) -> Result<()> {
    prepare_ledger_host_postgres_effect_runtime_chirho(
        root_chirho,
        host_chirho,
        ledger_config_chirho,
    )
    .map(|_prepared_chirho| ())
}

/// Operator-only read posture. The caller supplies no effect, money, depth, K, or provider
/// coordinate; the opaque authority is minted inside the locked host from current verified state.
pub fn preview_current_ledger_host_postgres_compensation_chirho(
    runtime_chirho: &SharedLedgerHostPostgresEffectRuntimeChirho,
    root_chirho: &Path,
    app_chirho: &str,
    owner_chirho: &str,
) -> Result<CurrentPostgresCompensationPreviewChirho> {
    runtime_chirho.with_host_port_chirho(|port_chirho| {
        port_chirho.preview_current_compensation_chirho(root_chirho, app_chirho, owner_chirho)
    })
}

/// Operator-only execute posture. The same mutex serializes re-preview and the provider
/// transaction; a committed terminal remains truth even if its projection re-feed is delayed.
pub fn execute_current_ledger_host_postgres_compensation_chirho(
    runtime_chirho: &SharedLedgerHostPostgresEffectRuntimeChirho,
    root_chirho: &Path,
    app_chirho: &str,
    owner_chirho: &str,
) -> Result<CurrentPostgresCompensationExecutionChirho> {
    runtime_chirho.with_host_port_chirho(|port_chirho| {
        port_chirho.execute_current_compensation_chirho(root_chirho, app_chirho, owner_chirho)
    })
}

/// Execute one fixed current-writer loss witness through the actor's complete mutation envelope.
/// Ask the live resident actor to activate a tenant-root migration target.
///
/// The caller supplies only a PATH. The eligibility precheck is computed inside the RESIDENT ACTOR,
/// which is the only layer that knows the configured ledger namespace name — a root whose namespace
/// sits under an operator-chosen directory refuses on its own journal's parent otherwise.
pub fn activate_current_ledger_host_tenant_migration_target_chirho(
    runtime_chirho: &SharedLedgerHostPostgresEffectRuntimeChirho,
    target_root_chirho: &Path,
) -> std::result::Result<
    ResidentTenantMigrationTargetActivatedStatusChirho,
    ResidentTenantMigrationOperationRefusalChirho,
> {
    runtime_chirho.with_tenant_migration_activation_port_chirho(|port_chirho| {
        port_chirho.activate_current_tenant_migration_target_chirho(target_root_chirho)
    })
}

/// Ask the live resident actor to begin an attempt and fence the source.
///
/// The caller supplies a path and an externally signed destination authorization. It supplies no
/// preliminary check: that type cannot be built outside the actor, on purpose.
pub fn begin_current_ledger_host_tenant_migration_source_fence_chirho(
    runtime_chirho: &SharedLedgerHostPostgresEffectRuntimeChirho,
    target_root_chirho: &Path,
    destination_chirho: TenantMigrationDestinationRecordChirho,
    writer_adoption_chirho: Option<TenantMigrationWriterAdoptionRecordChirho>,
) -> std::result::Result<
    ResidentTenantMigrationSourceFenceStatusChirho,
    ResidentTenantMigrationOperationRefusalChirho,
> {
    runtime_chirho.with_tenant_migration_activation_port_chirho(|port_chirho| {
        port_chirho.begin_current_tenant_migration_source_fence_chirho(
            target_root_chirho,
            destination_chirho,
            writer_adoption_chirho,
        )
    })
}

pub fn execute_current_ledger_host_testkind_loss_witness_chirho(
    runtime_chirho: &SharedLedgerHostPostgresEffectRuntimeChirho,
    phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
) -> std::result::Result<
    ResidentTestkindLossWitnessOutcomeChirho,
    ResidentTestkindLossWitnessRefusalChirho,
> {
    runtime_chirho.with_testkind_loss_witness_port_chirho(|port_chirho| {
        port_chirho.execute_current_testkind_loss_witness_chirho(phase_chirho)
    })
}

/// Execute the SECOND post-adoption current-writer witness, giving the canary window a span.
pub fn execute_sustained_ledger_host_testkind_loss_witness_chirho(
    runtime_chirho: &SharedLedgerHostPostgresEffectRuntimeChirho,
    phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
) -> std::result::Result<
    ResidentTestkindLossWitnessOutcomeChirho,
    ResidentTestkindLossWitnessRefusalChirho,
> {
    runtime_chirho.with_testkind_loss_witness_port_chirho(|port_chirho| {
        port_chirho.execute_sustained_testkind_loss_witness_chirho(phase_chirho)
    })
}

/// Execute the sink-only deposed-writer refusal witness without exposing broader journal authority.
pub fn execute_deposed_sink_ledger_host_testkind_loss_witness_chirho(
    runtime_chirho: &SharedLedgerHostPostgresEffectRuntimeChirho,
    phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
) -> std::result::Result<
    ResidentTestkindLossWitnessOutcomeChirho,
    ResidentTestkindLossWitnessRefusalChirho,
> {
    runtime_chirho.with_testkind_loss_witness_port_chirho(|port_chirho| {
        port_chirho.execute_deposed_sink_testkind_loss_witness_chirho(phase_chirho)
    })
}

/// Execute only the exact preview the operator reviewed.
///
/// The fresh preview and execution share the runtime's one provider mutex, so a served request
/// cannot replace the current effect between the comparison and mutation.
pub fn execute_reviewed_current_ledger_host_postgres_compensation_chirho(
    runtime_chirho: &SharedLedgerHostPostgresEffectRuntimeChirho,
    root_chirho: &Path,
    app_chirho: &str,
    owner_chirho: &str,
    expected_preview_chirho: &CurrentPostgresCompensationPreviewChirho,
) -> Result<CurrentPostgresCompensationExecutionChirho> {
    runtime_chirho.with_host_port_chirho(|port_chirho| {
        let current_preview_chirho = port_chirho.preview_current_compensation_chirho(
            root_chirho,
            app_chirho,
            owner_chirho,
        )?;
        if &current_preview_chirho != expected_preview_chirho {
            return Err(
                ReviewedCurrentPostgresCompensationRefusalChirho::PreviewChangedChirho.into(),
            );
        }
        if !matches!(
            current_preview_chirho.verdict_chirho,
            CurrentPostgresCompensationPreviewVerdictChirho::ExecutableChirho
        ) {
            return Err(
                ReviewedCurrentPostgresCompensationRefusalChirho::PreviewNotExecutableChirho.into(),
            );
        }
        port_chirho.execute_current_compensation_chirho(root_chirho, app_chirho, owner_chirho)
    })
}

/// Replay only an already-completed compensation and require byte-equivalent typed execution
/// evidence. The completed-preview check and provider replay share the one provider mutex, so this
/// verb can never become the first execution through a race.
pub fn replay_completed_current_ledger_host_postgres_compensation_chirho(
    runtime_chirho: &SharedLedgerHostPostgresEffectRuntimeChirho,
    root_chirho: &Path,
    app_chirho: &str,
    owner_chirho: &str,
    expected_execution_chirho: &CurrentPostgresCompensationExecutionChirho,
) -> Result<CurrentPostgresCompensationExecutionChirho> {
    runtime_chirho.with_host_port_chirho(|port_chirho| {
        let current_preview_chirho = port_chirho.preview_current_compensation_chirho(
            root_chirho,
            app_chirho,
            owner_chirho,
        )?;
        if !matches!(
            current_preview_chirho.verdict_chirho,
            CurrentPostgresCompensationPreviewVerdictChirho::CompletedReplayChirho {
                provider_restored_chirho: true
            }
        ) {
            return Err(
                ReviewedCurrentPostgresCompensationRefusalChirho::ReplayNotCompletedChirho.into(),
            );
        }
        let replay_chirho = port_chirho.execute_current_compensation_chirho(
            root_chirho,
            app_chirho,
            owner_chirho,
        )?;
        if &replay_chirho != expected_execution_chirho {
            return Err(
                ReviewedCurrentPostgresCompensationRefusalChirho::ReplayExecutionChangedChirho
                    .into(),
            );
        }
        Ok(replay_chirho)
    })
}

fn connect_local_phase_b_database_chirho(
    root_chirho: &Path,
    connection_secret_name_chirho: &str,
) -> Result<PostgresDatabaseChirho> {
    let connection_ref_chirho =
        secret_ref_chirho(connection_secret_name_chirho).map_err(|_error_chirho| {
            LedgerHostPostgresEffectRefusalChirho::ConnectionSecretUnavailableChirho
        })?;
    let connection_secret_chirho = resolve_secret_ref_chirho(root_chirho, &connection_ref_chirho)
        .map_err(|_error_chirho| {
        LedgerHostPostgresEffectRefusalChirho::ConnectionSecretUnavailableChirho
    })?;
    let connection_config_chirho = std::str::from_utf8(connection_secret_chirho.as_bytes_chirho())
        .map_err(|_error_chirho| {
            LedgerHostPostgresEffectRefusalChirho::ConnectionSecretUnavailableChirho
        })?;
    let connection_config_chirho =
        parse_local_phase_b_connection_config_chirho(connection_config_chirho)?;
    let client_chirho = connection_config_chirho
        .connect(NoTls)
        .map_err(|_error_chirho| {
            LedgerHostPostgresEffectRefusalChirho::ConnectionUnavailableChirho
        })?;
    let mut database_chirho = PostgresDatabaseChirho::from_client_chirho(client_chirho);
    database_chirho
        .verify_schema_ready_chirho()
        .map_err(|_error_chirho| {
            LedgerHostPostgresEffectRefusalChirho::DatabaseSchemaUnavailableChirho
        })?;
    Ok(database_chirho)
}

/// The ONE LocalPhaseB DSN law (#6056): an explicit LOCAL endpoint — Unix socket, localhost, or
/// loopback IP (v4/v6), including hostaddrs — and nothing else. Both the served runtime and the
/// credits-demo smoke setup preflight through THIS function; a second same-shaped parser anywhere
/// would be drift between what serving accepts and what evidence verifies.
pub fn parse_local_phase_b_connection_config_chirho(connection_chirho: &str) -> Result<Config> {
    let config_chirho = connection_chirho
        .parse::<Config>()
        .map_err(|_error_chirho| {
            LedgerHostPostgresEffectRefusalChirho::ConnectionSecretUnavailableChirho
        })?;
    let hosts_chirho = config_chirho.get_hosts();
    let addresses_chirho = config_chirho.get_hostaddrs();
    let has_explicit_local_endpoint_chirho =
        !hosts_chirho.is_empty() || !addresses_chirho.is_empty();
    let hosts_are_local_chirho = hosts_chirho.iter().all(|host_chirho| match host_chirho {
        Host::Tcp(host_chirho) => {
            host_chirho.eq_ignore_ascii_case("localhost")
                || host_chirho
                    .parse::<IpAddr>()
                    .is_ok_and(|address_chirho| address_chirho.is_loopback())
        }
        #[cfg(unix)]
        Host::Unix(_path_chirho) => true,
    });
    let addresses_are_local_chirho = addresses_chirho.iter().all(IpAddr::is_loopback);
    if !has_explicit_local_endpoint_chirho || !hosts_are_local_chirho || !addresses_are_local_chirho
    {
        return Err(
            LedgerHostPostgresEffectRefusalChirho::ConnectionOutsideLocalPhaseBChirho.into(),
        );
    }
    Ok(config_chirho)
}

fn verify_current_billing_kind_for_host_chirho(
    host_chirho: &LedgerHostProjectionReadPortChirho,
    billing_kind_chirho: &AssetKindIdChirho,
) -> Result<()> {
    let registry_chirho = host_chirho
        .load_kind_registry_chirho()
        .map_err(|_error_chirho| {
            LedgerHostPostgresEffectRefusalChirho::BillingKindUnavailableChirho
        })?;
    let projection_chirho = registry_chirho
        .kinds_chirho
        .get(billing_kind_chirho)
        .ok_or(LedgerHostPostgresEffectRefusalChirho::BillingKindUnavailableChirho)?;
    if projection_chirho
        .current_policy_chirho
        .settlement_owner_chirho
        .is_none()
    {
        return Err(LedgerHostPostgresEffectRefusalChirho::BillingKindUnavailableChirho.into());
    }
    Ok(())
}

fn current_feed_routes_for_host_chirho(
    host_chirho: &LedgerHostProjectionReadPortChirho,
) -> Result<Vec<(String, DigestChirho)>> {
    let registry_chirho = load_verified_projection_registry_chirho(
        &host_chirho.storage_chirho,
        host_chirho.signers_chirho.config_signer_chirho(),
        &host_chirho.projection_registry_path_chirho,
        &host_chirho.projection_registry_id_chirho,
    )
    .map_err(|_error_chirho| {
        LedgerHostPostgresEffectRefusalChirho::ProjectionRouteUnavailableChirho
    })?;
    host_chirho
        .projection_routes_chirho
        .keys()
        .map(|projection_name_chirho| {
            let state_chirho = registry_chirho
                .projections_chirho
                .get(projection_name_chirho)
                .ok_or(LedgerHostPostgresEffectRefusalChirho::ProjectionRouteUnavailableChirho)?;
            if state_chirho.retired_chirho
                || state_chirho.current_descriptor_chirho.fold_fn_ref_chirho
                    != account_net_projection_fold_ref_chirho()
                || state_chirho.current_descriptor_chirho.cost_class_chirho
                    != ProjectionCostClassChirho::StandingWriteRateChirho
            {
                return Err(
                    LedgerHostPostgresEffectRefusalChirho::ProjectionRouteUnavailableChirho.into(),
                );
            }
            Ok((
                projection_name_chirho.clone(),
                state_chirho.current_digest_chirho.clone(),
            ))
        })
        .collect()
}

impl LedgerHostPostgresEffectRuntimeChirho {
    fn current_feed_routes_chirho(&self) -> Result<Vec<(String, DigestChirho)>> {
        current_feed_routes_for_host_chirho(&self.host_chirho)
    }

    fn feed_all_current_routes_chirho(&self) -> Result<()> {
        let routes_chirho = self.current_feed_routes_chirho()?;
        let kind_registry_chirho =
            self.host_chirho
                .load_kind_registry_chirho()
                .map_err(|_error_chirho| {
                    LedgerHostPostgresEffectRefusalChirho::ProjectionFeedUnavailableChirho
                })?;
        let authority_chirho = PlatformPolicyMintAuthorityChirho::new_chirho(&kind_registry_chirho);
        let journal_ports_chirho = JournalPortsChirho {
            storage_chirho: &self.host_chirho.storage_chirho,
            signer_chirho: self.host_chirho.signers_chirho.journal_signer_chirho(),
            clock_chirho: &self.host_chirho.clock_chirho,
            membership_chirho: &self.host_chirho.membership_chirho,
            kind_registry_chirho: &kind_registry_chirho,
            authority_chirho: &authority_chirho,
        };
        let read_chirho = LedgerReadCompositionChirho {
            journal_ports_chirho,
            config_root_chirho: self.host_chirho.signers_chirho.config_signer_chirho(),
            feeder_root_chirho: self.host_chirho.signers_chirho.feeder_signer_chirho(),
            projection_registry_path_chirho: self
                .host_chirho
                .projection_registry_path_chirho
                .clone(),
            projection_registry_id_chirho: self.host_chirho.projection_registry_id_chirho.clone(),
            source_registry_path_chirho: self.host_chirho.source_registry_path_chirho.clone(),
            source_registry_id_chirho: self.host_chirho.source_registry_id_chirho.clone(),
        };
        let fold_chirho = AccountNetProjectionFoldChirho;
        feed_every_configured_route_chirho(
            routes_chirho,
            |(projection_name_chirho, descriptor_digest_chirho)| {
                let head_path_chirho = self
                    .host_chirho
                    .projection_routes_chirho
                    .get(&projection_name_chirho)
                    .ok_or(
                        LedgerHostPostgresEffectRefusalChirho::ProjectionRouteUnavailableChirho,
                    )?;
                read_chirho
                    .feed_and_publish_chirho(
                        &projection_name_chirho,
                        &descriptor_digest_chirho,
                        &fold_chirho,
                        ProjectionSourceChirho {
                            journal_ports_chirho,
                            journal_path_chirho: &self.host_chirho.journal_path_chirho,
                            cluster_chirho: &self.host_chirho.cluster_chirho,
                        },
                        head_path_chirho,
                    )
                    .map(|_projection_chirho| ())
            },
        )
    }
}

fn feed_every_configured_route_chirho<RouteChirho>(
    routes_chirho: impl IntoIterator<Item = RouteChirho>,
    mut feed_chirho: impl FnMut(RouteChirho) -> Result<()>,
) -> Result<()> {
    let mut any_refused_chirho = false;
    for route_chirho in routes_chirho {
        if feed_chirho(route_chirho).is_err() {
            any_refused_chirho = true;
        }
    }
    if any_refused_chirho {
        return Err(LedgerHostPostgresEffectRefusalChirho::ProjectionFeedUnavailableChirho.into());
    }
    Ok(())
}

fn refeed_committed_terminal_chirho(
    disposition_chirho: &EffectTerminalDispositionChirho,
    feed_chirho: impl FnOnce() -> Result<()>,
) {
    if matches!(
        disposition_chirho,
        EffectTerminalDispositionChirho::CommittedChirho { .. }
    ) {
        // The terminal is already signed and durable. A feed failure must not rewrite that truth
        // as a failed effect; the old head remains and the next read classifies non-Fresh.
        let _committed_feed_refusal_chirho = feed_chirho().err();
    }
}

impl PostgresReversibleRuntimePortChirho for LedgerHostPostgresEffectRuntimeChirho {
    fn execute_chirho(
        &mut self,
        execution_chirho: PostgresReversibleExecutionChirho<'_>,
    ) -> Result<Vec<u8>> {
        if execution_chirho.root_chirho() != self.root_chirho {
            return Err(LedgerHostPostgresEffectRefusalChirho::ForeignRootChirho.into());
        }
        let money_policy_chirho = AppPriceBookUserPaysPolicyChirho;
        let mut composition_chirho = LocalPostgresEffectCompositionChirho::open_chirho(
            &self.root_chirho,
            &mut self.journal_chirho,
            &mut self.database_chirho,
            self.host_chirho
                .signers_chirho
                .effect_intent_signer_chirho(),
            self.host_chirho
                .signers_chirho
                .effect_terminal_signer_chirho(),
            &money_policy_chirho,
            self.billing_kind_chirho.clone(),
        )?;
        let terminal_bytes_chirho = composition_chirho.execute_chirho(execution_chirho)?;
        drop(composition_chirho);
        let disposition_chirho =
            parse_canonical_postgres_effect_terminal_disposition_chirho(&terminal_bytes_chirho)?;
        refeed_committed_terminal_chirho(&disposition_chirho, || {
            self.feed_all_current_routes_chirho()
        });
        Ok(terminal_bytes_chirho)
    }
}

impl LedgerHostPostgresEffectPortChirho for LedgerHostPostgresEffectRuntimeChirho {
    fn runtime_port_chirho(&mut self) -> &mut dyn PostgresReversibleRuntimePortChirho {
        self
    }

    fn preview_current_compensation_chirho(
        &mut self,
        root_chirho: &Path,
        app_chirho: &str,
        owner_chirho: &str,
    ) -> Result<CurrentPostgresCompensationPreviewChirho> {
        if root_chirho != self.root_chirho {
            return Err(LedgerHostPostgresEffectRefusalChirho::ForeignRootChirho.into());
        }
        let plan_authority_chirho = mint_verified_current_undo_plan_authority_chirho(
            root_chirho,
            app_chirho,
            owner_chirho,
        )?;
        let money_policy_chirho = AppPriceBookUserPaysPolicyChirho;
        let mut composition_chirho = LocalPostgresEffectCompositionChirho::open_chirho(
            root_chirho,
            &mut self.journal_chirho,
            &mut self.database_chirho,
            self.host_chirho
                .signers_chirho
                .effect_intent_signer_chirho(),
            self.host_chirho
                .signers_chirho
                .effect_terminal_signer_chirho(),
            &money_policy_chirho,
            self.billing_kind_chirho.clone(),
        )?;
        composition_chirho
            .preview_current_compensation_chirho(&plan_authority_chirho)
            .map_err(Into::into)
    }

    fn execute_current_compensation_chirho(
        &mut self,
        root_chirho: &Path,
        app_chirho: &str,
        owner_chirho: &str,
    ) -> Result<CurrentPostgresCompensationExecutionChirho> {
        if root_chirho != self.root_chirho {
            return Err(LedgerHostPostgresEffectRefusalChirho::ForeignRootChirho.into());
        }
        let plan_authority_chirho = mint_verified_current_undo_plan_authority_chirho(
            root_chirho,
            app_chirho,
            owner_chirho,
        )?;
        let money_policy_chirho = AppPriceBookUserPaysPolicyChirho;
        let mut composition_chirho = LocalPostgresEffectCompositionChirho::open_chirho(
            root_chirho,
            &mut self.journal_chirho,
            &mut self.database_chirho,
            self.host_chirho
                .signers_chirho
                .effect_intent_signer_chirho(),
            self.host_chirho
                .signers_chirho
                .effect_terminal_signer_chirho(),
            &money_policy_chirho,
            self.billing_kind_chirho.clone(),
        )?;
        let execution_chirho =
            composition_chirho.execute_current_compensation_chirho(&plan_authority_chirho)?;
        drop(composition_chirho);
        refeed_committed_terminal_chirho(&execution_chirho.disposition_chirho, || {
            self.feed_all_current_routes_chirho()
        });
        Ok(execution_chirho)
    }

    fn execute_current_testkind_loss_witness_chirho(
        &mut self,
        phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    ) -> std::result::Result<
        ResidentTestkindLossWitnessOutcomeChirho,
        ResidentTestkindLossWitnessRefusalChirho,
    > {
        self.journal_chirho
            .testkind_loss_witness_handle_chirho()?
            .execute_current_chirho(phase_chirho)
    }

    fn activate_current_tenant_migration_target_chirho(
        &mut self,
        target_root_chirho: &Path,
    ) -> std::result::Result<
        ResidentTenantMigrationTargetActivatedStatusChirho,
        ResidentTenantMigrationOperationRefusalChirho,
    > {
        self.journal_chirho
            .tenant_migration_operation_handle_chirho()?
            .activate_target_chirho(target_root_chirho)
    }

    fn begin_current_tenant_migration_source_fence_chirho(
        &mut self,
        target_root_chirho: &Path,
        destination_chirho: TenantMigrationDestinationRecordChirho,
        writer_adoption_chirho: Option<TenantMigrationWriterAdoptionRecordChirho>,
    ) -> std::result::Result<
        ResidentTenantMigrationSourceFenceStatusChirho,
        ResidentTenantMigrationOperationRefusalChirho,
    > {
        self.journal_chirho
            .tenant_migration_operation_handle_chirho()?
            .begin_source_fence_with_writer_adoption_chirho(
                target_root_chirho,
                destination_chirho,
                writer_adoption_chirho,
            )
    }

    fn execute_sustained_testkind_loss_witness_chirho(
        &mut self,
        phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    ) -> std::result::Result<
        ResidentTestkindLossWitnessOutcomeChirho,
        ResidentTestkindLossWitnessRefusalChirho,
    > {
        self.journal_chirho
            .testkind_loss_witness_handle_chirho()?
            .execute_sustained_chirho(phase_chirho)
    }

    fn execute_deposed_sink_testkind_loss_witness_chirho(
        &mut self,
        phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    ) -> std::result::Result<
        ResidentTestkindLossWitnessOutcomeChirho,
        ResidentTestkindLossWitnessRefusalChirho,
    > {
        self.journal_chirho
            .testkind_loss_witness_handle_chirho()?
            .execute_deposed_sink_chirho(phase_chirho)
    }
}
