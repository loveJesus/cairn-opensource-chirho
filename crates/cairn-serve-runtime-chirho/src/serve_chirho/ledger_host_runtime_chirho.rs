// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Open-only CF6 host composition for verified published-projection reads, and the bundle of host authorities serve
//! is built with (moved here from `serve_chirho.rs`, repaying brick 4a's size loan).
//!
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf6-regenesis-boundary-chirho.md`.
//! Configuration owns every filesystem and authority coordinate. Construction verifies existing
//! state without writing it; request strings can select only an exact configured projection name.

#[path = "ledger_host_runtime_chirho/monitor_chirho.rs"]
mod monitor_chirho;
#[path = "ledger_host_runtime_chirho/postgres_effect_chirho.rs"]
mod postgres_effect_chirho;

pub use monitor_chirho::{
    parse_ledger_conservation_cycle_row_chirho, LedgerConservationCycleOutcomeChirho,
    LedgerConservationCycleRowChirho, LedgerConservationCycleWireRefusalChirho,
    LedgerConservationHeadEvidenceChirho, LedgerConservationIncidentEvidenceChirho,
    LedgerConservationRefusalCodeChirho, LEDGER_CONSERVATION_CYCLE_SCHEMA_V1_CHIRHO,
};
pub(crate) use monitor_chirho::{
    FixedLedgerConservationAlarmChirho, LedgerConservationAlarmPortChirho,
    LedgerMonitorCadenceWaitPortChirho, TokioLedgerMonitorCadenceWaitChirho,
};
pub use postgres_effect_chirho::{
    activate_current_ledger_host_tenant_migration_target_chirho,
    begin_current_ledger_host_tenant_migration_source_fence_chirho,
    execute_current_ledger_host_postgres_compensation_chirho,
    execute_current_ledger_host_testkind_loss_witness_chirho,
    execute_deposed_sink_ledger_host_testkind_loss_witness_chirho,
    execute_reviewed_current_ledger_host_postgres_compensation_chirho,
    execute_sustained_ledger_host_testkind_loss_witness_chirho,
    open_shared_ledger_host_postgres_effect_runtime_chirho,
    open_shared_ledger_host_postgres_effect_runtime_with_resident_journal_chirho,
    parse_local_phase_b_connection_config_chirho,
    preflight_ledger_host_postgres_effect_runtime_chirho,
    preview_current_ledger_host_postgres_compensation_chirho,
    replay_completed_current_ledger_host_postgres_compensation_chirho,
    LedgerHostPostgresEffectRefusalChirho, ReviewedCurrentPostgresCompensationRefusalChirho,
    SharedLedgerHostPostgresEffectRuntimeChirho,
};

use anyhow::{bail, Result};
use cairn_chirho::effect_chirho::projection_read_chirho::{
    PublishedProjectionReadPortChirho, PublishedProjectionReadRequestChirho,
};
use cairn_config_chirho::config_chirho::LedgerHostConfigChirho;
use cairn_kind_registry_chirho::chain_chirho::{
    load_verified_registry_chirho, KindRegistryPortsChirho, VerifiedRegistryChirho,
};
use cairn_ledger_composition_chirho::{
    ComposedProjectionReadChirho, FollowerServeOutcomeChirho, LedgerReadCompositionChirho,
};
use cairn_ledger_host_chirho::{
    host_ledger_signer_refs_from_config_chirho, verify_host_ledger_config_custody_chirho,
    FsLedgerStorageChirho, FsMonitorEvidenceSinkChirho, HostLedgerSignersChirho,
    PinnedKindIssuerVerifierChirho, PlatformPolicyMintAuthorityChirho,
    StaticClusterMembershipChirho, SystemLedgerClockChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{JournalPortsChirho, LedgerJournalChirho};
use cairn_ledger_log_chirho::ports_chirho::StoragePathChirho;
use cairn_ledger_model_chirho::ids_chirho::{ClusterIdChirho, MoneyGroupIdChirho};
use cairn_ledger_read_model_chirho::feeder_chirho::ProjectionSourceChirho;
use cairn_ledger_read_model_chirho::localphaseb_evidence_chirho::LocalPhaseBEvidencePortsChirho;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LedgerHostRuntimeRefusalChirho {
    ProjectionNotConfiguredChirho,
    ProjectionPreflightUnavailableChirho,
    ProjectionPreflightRefusedChirho,
    ConservationCycleUnavailableChirho,
}

impl fmt::Display for LedgerHostRuntimeRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(match self {
            Self::ProjectionNotConfiguredChirho => {
                "published projection is outside the configured host routes"
            }
            Self::ProjectionPreflightUnavailableChirho => {
                "configured published projection is unavailable during startup verification"
            }
            Self::ProjectionPreflightRefusedChirho => {
                "configured published projection failed its verified startup gate"
            }
            Self::ConservationCycleUnavailableChirho => {
                "ledger conservation cycle serialization is unavailable"
            }
        })
    }
}

impl Error for LedgerHostRuntimeRefusalChirho {}

/// Fully-verified LocalPhaseB substrate balances read through the read-only journal door (the signed
/// journal prefix is replayed and every account post-state re-derived by the verified fold). Per
/// account it carries the canonical account net = `credits − debits` (the sealed net_money law — a
/// Hold changes AVAILABILITY, not OWNERSHIP, so net EXCLUDES held), the authoritative escrow `held`,
/// and the verified tail seq; `net_supply_by_kind` is the journal's NET supply (minted − burned) per
/// kind. Conservation is `mint == sum(account_nets)` with the initial mint bound from the verified
/// regenesis receipt/plan (never conflated with net-supply). A leaked Hold leaves net UNCHANGED
/// while `held` rises, so escrow evidence asserts `held` directly (net cannot prove a Release); the
/// verified net deltas + `held` + `tail_seq` bind the L2 charge, the same-K replay no-op, and the
/// distinct-K Hold→Release pair to real journal movement rather than an untrusted raw re-read. Plain
/// string/int types so callers need no ledger-model dependency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerSubstrateBalancesChirho {
    pub account_nets_chirho: BTreeMap<(String, String), u64>,
    pub account_held_chirho: BTreeMap<(String, String), u64>,
    pub net_supply_by_kind_chirho: BTreeMap<String, u64>,
    pub tail_seq_chirho: u64,
    /// The EXACT cut identity of this snapshot (#6050 HOLD B): a seq alone is not a cut — a
    /// same-seq different-prefix fork could be joined to other evidence — so every balances read
    /// carries the verified genesis instance digest and the tail stored-line digest (hex).
    pub genesis_digest_chirho: String,
    pub tail_line_digest_chirho: String,
}

/// The one production projection-read adapter. It owns driven ports and immutable coordinates;
/// each read reloads current signed registries and fully verifies the journal through the
/// read-only door before returning a verdict.
pub struct LedgerHostProjectionReadPortChirho {
    storage_chirho: FsLedgerStorageChirho,
    monitor_evidence_sink_chirho: FsMonitorEvidenceSinkChirho,
    signers_chirho: HostLedgerSignersChirho,
    clock_chirho: SystemLedgerClockChirho,
    membership_chirho: StaticClusterMembershipChirho,
    issuer_verify_chirho: PinnedKindIssuerVerifierChirho,
    cluster_chirho: ClusterIdChirho,
    money_group_chirho: MoneyGroupIdChirho,
    journal_path_chirho: StoragePathChirho,
    kind_registry_path_chirho: StoragePathChirho,
    kind_registry_id_chirho: String,
    projection_registry_path_chirho: StoragePathChirho,
    projection_registry_id_chirho: String,
    source_registry_path_chirho: StoragePathChirho,
    source_registry_id_chirho: String,
    projection_routes_chirho: BTreeMap<String, StoragePathChirho>,
    monitor_evidence_path_chirho: String,
    monitor_cadence_ms_chirho: u64,
    conservation_cycle_lock_chirho: Mutex<()>,
}

struct EffectHostExactCutProjectionReadPortChirho {
    host_chirho: Arc<LedgerHostProjectionReadPortChirho>,
}

#[derive(Clone, Copy)]
enum LedgerHostProjectionFreshnessPostureChirho {
    LagWindowChirho,
    EffectHostExactCutChirho,
}

pub(super) fn effect_host_projection_read_port_chirho(
    host_chirho: Arc<LedgerHostProjectionReadPortChirho>,
) -> Arc<dyn PublishedProjectionReadPortChirho> {
    Arc::new(EffectHostExactCutProjectionReadPortChirho { host_chirho })
}

impl LedgerHostProjectionReadPortChirho {
    /// Open one already-provisioned host composition. No directory, key, registry, journal,
    /// projection, checkpoint, or operational-evidence row is created here.
    pub fn open_existing_chirho(
        selected_root_chirho: &Path,
        config_path_chirho: &Path,
        config_chirho: &LedgerHostConfigChirho,
    ) -> Result<Self> {
        config_chirho.validate_chirho()?;
        verify_host_ledger_config_custody_chirho(selected_root_chirho, config_path_chirho)?;

        let storage_namespace_chirho =
            selected_root_chirho.join(&config_chirho.storage_namespace_chirho);
        let monitor_namespace_chirho =
            selected_root_chirho.join(&config_chirho.monitor_evidence_namespace_chirho);
        let storage_chirho =
            FsLedgerStorageChirho::open_existing_chirho(&storage_namespace_chirho)?;
        let monitor_evidence_sink_chirho =
            FsMonitorEvidenceSinkChirho::open_existing_disjoint_chirho(
                &storage_chirho,
                &monitor_namespace_chirho,
            )?;
        let signer_refs_chirho =
            host_ledger_signer_refs_from_config_chirho(&config_chirho.signer_secrets_chirho)?;
        let signers_chirho = HostLedgerSignersChirho::load_existing_chirho(
            selected_root_chirho,
            &signer_refs_chirho,
        )?;
        let membership_chirho = StaticClusterMembershipChirho::from_config_chirho(
            config_chirho.local_epoch_chirho,
            &config_chirho.members_chirho,
        )?;
        let issuer_verify_chirho =
            PinnedKindIssuerVerifierChirho::from_config_chirho(&config_chirho.kind_issuer_chirho)?;
        let projection_routes_chirho = config_chirho
            .projection_routes_chirho
            .iter()
            .map(|route_chirho| {
                (
                    route_chirho.projection_name_chirho.clone(),
                    StoragePathChirho::new_chirho(&route_chirho.head_path_chirho),
                )
            })
            .collect();
        let port_chirho = Self {
            storage_chirho,
            monitor_evidence_sink_chirho,
            signers_chirho,
            clock_chirho: SystemLedgerClockChirho,
            membership_chirho,
            issuer_verify_chirho,
            cluster_chirho: ClusterIdChirho(config_chirho.cluster_id_chirho.clone()),
            money_group_chirho: MoneyGroupIdChirho(config_chirho.money_group_id_chirho.clone()),
            journal_path_chirho: StoragePathChirho::new_chirho(&config_chirho.journal_path_chirho),
            kind_registry_path_chirho: StoragePathChirho::new_chirho(
                &config_chirho.kind_registry_path_chirho,
            ),
            kind_registry_id_chirho: config_chirho.kind_registry_id_chirho.clone(),
            projection_registry_path_chirho: StoragePathChirho::new_chirho(
                &config_chirho.projection_registry_path_chirho,
            ),
            projection_registry_id_chirho: config_chirho.projection_registry_id_chirho.clone(),
            source_registry_path_chirho: StoragePathChirho::new_chirho(
                &config_chirho.source_registry_path_chirho,
            ),
            source_registry_id_chirho: config_chirho.source_registry_id_chirho.clone(),
            projection_routes_chirho,
            monitor_evidence_path_chirho: config_chirho.monitor_evidence_path_chirho.clone(),
            monitor_cadence_ms_chirho: config_chirho.monitor_cadence_ms_chirho,
            conservation_cycle_lock_chirho: Mutex::new(()),
        };
        port_chirho.preflight_chirho()?;
        Ok(port_chirho)
    }

    pub fn monitor_evidence_sink_chirho(&self) -> &FsMonitorEvidenceSinkChirho {
        &self.monitor_evidence_sink_chirho
    }

    pub fn monitor_evidence_path_chirho(&self) -> &str {
        &self.monitor_evidence_path_chirho
    }

    pub fn monitor_cadence_ms_chirho(&self) -> u64 {
        self.monitor_cadence_ms_chirho
    }

    pub fn money_group_chirho(&self) -> &MoneyGroupIdChirho {
        &self.money_group_chirho
    }

    fn preflight_chirho(&self) -> Result<()> {
        for (projection_name_chirho, head_path_chirho) in &self.projection_routes_chirho {
            let read_chirho = self
                .read_configured_projection_chirho(projection_name_chirho, head_path_chirho)
                .map_err(|_error_chirho| {
                    LedgerHostRuntimeRefusalChirho::ProjectionPreflightUnavailableChirho
                })?;
            if matches!(
                read_chirho.outcome_chirho,
                FollowerServeOutcomeChirho::GateRefusedChirho(_)
            ) {
                return Err(
                    LedgerHostRuntimeRefusalChirho::ProjectionPreflightRefusedChirho.into(),
                );
            }
        }
        Ok(())
    }

    /// Read fully-verified substrate balances through the read-only journal door (never repairs or
    /// truncates). The signed journal prefix is replayed and every account post-state re-derived, so
    /// callers get conservation-grade numbers (payer net, settlement net, minted supply) from the
    /// substrate authority rather than the disposable published projection.
    pub fn read_substrate_balances_chirho(&self) -> Result<LedgerSubstrateBalancesChirho> {
        let kind_registry_chirho = self.load_kind_registry_chirho()?;
        let authority_chirho = PlatformPolicyMintAuthorityChirho::new_chirho(&kind_registry_chirho);
        let journal_ports_chirho = JournalPortsChirho {
            storage_chirho: &self.storage_chirho,
            signer_chirho: self.signers_chirho.journal_signer_chirho(),
            clock_chirho: &self.clock_chirho,
            membership_chirho: &self.membership_chirho,
            kind_registry_chirho: &kind_registry_chirho,
            authority_chirho: &authority_chirho,
        };
        let journal_chirho = LedgerJournalChirho::open_read_only_chirho(
            journal_ports_chirho,
            self.journal_path_chirho.clone(),
            &self.cluster_chirho,
        )
        .map_err(|error_chirho| {
            anyhow::anyhow!("read-only substrate journal open failed: {error_chirho:?}")
        })?;
        let mut account_nets_chirho = BTreeMap::new();
        let mut account_held_chirho = BTreeMap::new();
        for (account_chirho, post_chirho) in journal_chirho.head_states_chirho() {
            // Canonical account net = credits − debits (the sealed net_money law); a Hold changes
            // availability, not ownership, so net EXCLUDES held. Held is surfaced separately so an
            // escrow leak (net unchanged, held risen) is visible and never folded into net.
            let net_chirho = post_chirho
                .credits_total_chirho
                .checked_sub(post_chirho.debits_total_chirho)
                .ok_or_else(|| anyhow::anyhow!("verified account net underflow"))?;
            let key_chirho = (
                account_chirho.owner_chirho.clone(),
                account_chirho.kind_id_chirho.0.clone(),
            );
            account_nets_chirho.insert(key_chirho.clone(), net_chirho);
            account_held_chirho.insert(key_chirho, post_chirho.held_chirho);
        }
        let net_supply_by_kind_chirho = journal_chirho
            .supply_by_kind_chirho()
            .iter()
            .map(|(kind_chirho, supply_chirho)| (kind_chirho.0.clone(), *supply_chirho))
            .collect();
        Ok(LedgerSubstrateBalancesChirho {
            account_nets_chirho,
            account_held_chirho,
            net_supply_by_kind_chirho,
            tail_seq_chirho: journal_chirho.tail_seq_chirho(),
            genesis_digest_chirho: journal_chirho.genesis_digest_chirho().0.clone(),
            tail_line_digest_chirho: journal_chirho.tail_line_digest_chirho().0.clone(),
        })
    }

    /// Scoped access to the host's VERIFIED projection-source ports, storage, feeder root, and the
    /// host-resolved FINAL head path for a requested configured projection — lent together to one
    /// closure for the LocalPhaseB packet-evidence support read. The raw ports exist only inside
    /// the closure (the caller cannot obtain, outlive, or substitute them — in particular "final"
    /// is resolved from the host's configured routes inside this seam, never caller-supplied), and
    /// the intended consumer is the packet-provenance-sealed constructor in the regenesis crate —
    /// serve-runtime deliberately does not depend on the packet types (direction-safe placement,
    /// #6050 HOLD A / #6052).
    /// Workflow: `spec-chirho/workflows-chirho/reversible-postgres-effect-chirho/credits-demo-localphaseb-smoke-chirho.md`.
    pub fn with_localphaseb_evidence_ports_chirho<T>(
        &self,
        projection_name_chirho: &str,
        f_chirho: impl FnOnce(LocalPhaseBEvidencePortsChirho<'_>) -> Result<T>,
    ) -> Result<T> {
        let final_head_path_chirho = self
            .projection_routes_chirho
            .get(projection_name_chirho)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "projection '{projection_name_chirho}' is not a configured serve route"
                )
            })?;
        let kind_registry_chirho = self.load_kind_registry_chirho()?;
        let authority_chirho = PlatformPolicyMintAuthorityChirho::new_chirho(&kind_registry_chirho);
        let journal_ports_chirho = JournalPortsChirho {
            storage_chirho: &self.storage_chirho,
            signer_chirho: self.signers_chirho.journal_signer_chirho(),
            clock_chirho: &self.clock_chirho,
            membership_chirho: &self.membership_chirho,
            kind_registry_chirho: &kind_registry_chirho,
            authority_chirho: &authority_chirho,
        };
        f_chirho(LocalPhaseBEvidencePortsChirho {
            source_chirho: ProjectionSourceChirho {
                journal_ports_chirho,
                journal_path_chirho: &self.journal_path_chirho,
                cluster_chirho: &self.cluster_chirho,
            },
            storage_chirho: &self.storage_chirho,
            feeder_root_chirho: self.signers_chirho.feeder_signer_chirho(),
            final_head_path_chirho,
        })
    }

    fn load_kind_registry_chirho(&self) -> Result<VerifiedRegistryChirho> {
        load_verified_registry_chirho(
            KindRegistryPortsChirho {
                storage_chirho: &self.storage_chirho,
                registry_root_chirho: self.signers_chirho.kind_root_signer_chirho(),
                issuer_verify_chirho: &self.issuer_verify_chirho,
            },
            &self.kind_registry_path_chirho,
            &self.kind_registry_id_chirho,
        )
        .map_err(|error_chirho| {
            anyhow::anyhow!("verified kind-registry load failed: {error_chirho:?}")
        })
    }

    fn read_configured_projection_chirho(
        &self,
        projection_name_chirho: &str,
        head_path_chirho: &StoragePathChirho,
    ) -> Result<ComposedProjectionReadChirho> {
        self.read_configured_projection_with_posture_chirho(
            projection_name_chirho,
            head_path_chirho,
            LedgerHostProjectionFreshnessPostureChirho::LagWindowChirho,
        )
    }

    fn read_configured_projection_with_posture_chirho(
        &self,
        projection_name_chirho: &str,
        head_path_chirho: &StoragePathChirho,
        freshness_posture_chirho: LedgerHostProjectionFreshnessPostureChirho,
    ) -> Result<ComposedProjectionReadChirho> {
        let kind_registry_chirho = self.load_kind_registry_chirho()?;
        let authority_chirho = PlatformPolicyMintAuthorityChirho::new_chirho(&kind_registry_chirho);
        let journal_ports_chirho = JournalPortsChirho {
            storage_chirho: &self.storage_chirho,
            signer_chirho: self.signers_chirho.journal_signer_chirho(),
            clock_chirho: &self.clock_chirho,
            membership_chirho: &self.membership_chirho,
            kind_registry_chirho: &kind_registry_chirho,
            authority_chirho: &authority_chirho,
        };
        let read_chirho = LedgerReadCompositionChirho {
            journal_ports_chirho,
            config_root_chirho: self.signers_chirho.config_signer_chirho(),
            feeder_root_chirho: self.signers_chirho.feeder_signer_chirho(),
            projection_registry_path_chirho: self.projection_registry_path_chirho.clone(),
            projection_registry_id_chirho: self.projection_registry_id_chirho.clone(),
            source_registry_path_chirho: self.source_registry_path_chirho.clone(),
            source_registry_id_chirho: self.source_registry_id_chirho.clone(),
        };
        let source_chirho = ProjectionSourceChirho {
            journal_ports_chirho,
            journal_path_chirho: &self.journal_path_chirho,
            cluster_chirho: &self.cluster_chirho,
        };
        match freshness_posture_chirho {
            LedgerHostProjectionFreshnessPostureChirho::LagWindowChirho => read_chirho
                .load_named_and_serve_with_view_chirho(
                    projection_name_chirho,
                    head_path_chirho,
                    source_chirho,
                ),
            LedgerHostProjectionFreshnessPostureChirho::EffectHostExactCutChirho => read_chirho
                .load_named_and_serve_with_view_exact_cut_chirho(
                    projection_name_chirho,
                    head_path_chirho,
                    source_chirho,
                ),
        }
    }

    fn read_published_projection_with_posture_chirho(
        &self,
        request_chirho: &PublishedProjectionReadRequestChirho<'_>,
        freshness_posture_chirho: LedgerHostProjectionFreshnessPostureChirho,
    ) -> Result<ComposedProjectionReadChirho> {
        let _verified_context_chirho = request_chirho.request_context_chirho;
        if request_chirho.requested_limit_chirho == 0 {
            bail!("published projection request limit must be nonzero");
        }
        let head_path_chirho = self
            .projection_routes_chirho
            .get(request_chirho.projection_name_chirho)
            .ok_or(LedgerHostRuntimeRefusalChirho::ProjectionNotConfiguredChirho)?;
        self.read_configured_projection_with_posture_chirho(
            request_chirho.projection_name_chirho,
            head_path_chirho,
            freshness_posture_chirho,
        )
    }
}

impl PublishedProjectionReadPortChirho for LedgerHostProjectionReadPortChirho {
    fn read_published_projection_chirho(
        &self,
        request_chirho: &PublishedProjectionReadRequestChirho<'_>,
    ) -> Result<ComposedProjectionReadChirho> {
        self.read_published_projection_with_posture_chirho(
            request_chirho,
            LedgerHostProjectionFreshnessPostureChirho::LagWindowChirho,
        )
    }
}

impl PublishedProjectionReadPortChirho for EffectHostExactCutProjectionReadPortChirho {
    fn read_published_projection_chirho(
        &self,
        request_chirho: &PublishedProjectionReadRequestChirho<'_>,
    ) -> Result<ComposedProjectionReadChirho> {
        self.host_chirho
            .read_published_projection_with_posture_chirho(
                request_chirho,
                LedgerHostProjectionFreshnessPostureChirho::EffectHostExactCutChirho,
            )
    }
}

// The serve composition: the host authorities serve is built with, its options, and the conservation monitor's task.
// Every field is `pub(super)`: the serve module's subtree, the scope these types had in `serve_chirho.rs`.
use super::{
    ConfiguredServeStartupPostureChirho, ServeAuthTokensChirho, ServedRequestAbuseLimitsChirho,
    ServedWriteRelayDestinationSlotChirho,
};
use cairn_write_relay_chirho::{ServedLocalReadAuthorityPortChirho, ServedWriteDispatchPortChirho};
use std::sync::atomic::AtomicBool;

pub(super) struct LedgerMonitorRuntimeChirho {
    pub(super) host_chirho: Arc<LedgerHostProjectionReadPortChirho>,
    pub(super) wait_chirho: Arc<dyn LedgerMonitorCadenceWaitPortChirho>,
    pub(super) alarm_chirho: Arc<dyn LedgerConservationAlarmPortChirho>,
}

/// Explicit host authorities passed into serve as one bundle. Construction has no ambient lookup;
/// an uncomposed bundle keeps projection reads and Descriptor-D effects typed-closed.
#[derive(Clone)]
pub struct ConfiguredLedgerHostRuntimePortsChirho {
    pub(super) ledger_host_chirho: Option<Arc<LedgerHostProjectionReadPortChirho>>,
    pub(super) postgres_effect_chirho: Option<SharedLedgerHostPostgresEffectRuntimeChirho>,
    pub(super) process_stop_chirho: Option<Arc<AtomicBool>>,
    pub(super) write_dispatch_chirho: Option<Arc<dyn ServedWriteDispatchPortChirho>>,
    pub(super) local_read_authority_chirho: Option<Arc<dyn ServedLocalReadAuthorityPortChirho>>,
    pub(super) write_destination_slot_chirho: Option<ServedWriteRelayDestinationSlotChirho>,
    pub(super) startup_posture_chirho: ConfiguredServeStartupPostureChirho,
}

impl ConfiguredLedgerHostRuntimePortsChirho {
    /// Build the legacy fail-closed posture with neither read nor effect authority.
    pub fn uncomposed_chirho() -> Self {
        Self {
            ledger_host_chirho: None,
            postgres_effect_chirho: None,
            process_stop_chirho: None,
            write_dispatch_chirho: None,
            local_read_authority_chirho: None,
            write_destination_slot_chirho: None,
            startup_posture_chirho:
                ConfiguredServeStartupPostureChirho::RecoverRunIntentsAndMonitorChirho,
        }
    }

    /// Bind one verified host read authority and its optional LocalPhaseB effect authority.
    pub fn composed_chirho(
        ledger_host_chirho: Arc<LedgerHostProjectionReadPortChirho>,
        postgres_effect_chirho: Option<SharedLedgerHostPostgresEffectRuntimeChirho>,
    ) -> Self {
        Self {
            ledger_host_chirho: Some(ledger_host_chirho),
            postgres_effect_chirho,
            process_stop_chirho: None,
            write_dispatch_chirho: None,
            local_read_authority_chirho: None,
            write_destination_slot_chirho: None,
            startup_posture_chirho:
                ConfiguredServeStartupPostureChirho::RecoverRunIntentsAndMonitorChirho,
        }
    }

    /// Bind serving to the same process stop signal as its surrounding transport.
    pub fn with_process_stop_chirho(mut self, process_stop_chirho: Arc<AtomicBool>) -> Self {
        self.process_stop_chirho = Some(process_stop_chirho);
        self
    }

    /// Compose the transport-neutral served dispatch and its process-local destination install
    /// slot. Neither value carries writer authority.
    pub fn with_served_write_relay_chirho(
        mut self,
        write_dispatch_chirho: Arc<dyn ServedWriteDispatchPortChirho>,
        local_read_authority_chirho: Arc<dyn ServedLocalReadAuthorityPortChirho>,
        write_destination_slot_chirho: ServedWriteRelayDestinationSlotChirho,
    ) -> Self {
        self.write_dispatch_chirho = Some(write_dispatch_chirho);
        self.local_read_authority_chirho = Some(local_read_authority_chirho);
        self.write_destination_slot_chirho = Some(write_destination_slot_chirho);
        self
    }

    /// Suppress every serve-startup durable mutation on an elected relay-only follower.
    ///
    /// The selected root is checked again by `serve_with_configured_ledger_host_chirho`; this
    /// builder only closes composition mistakes before startup.
    pub fn with_relay_only_follower_startup_chirho(mut self) -> Result<Self> {
        if self.postgres_effect_chirho.is_some()
            || self.write_dispatch_chirho.is_none()
            || self.local_read_authority_chirho.is_none()
            || self.write_destination_slot_chirho.is_none()
        {
            anyhow::bail!(
                "RelayOnlyFollowerStartupCompositionInvalidChirho: relay-only startup requires no effect runtime and both relay ports"
            );
        }
        self.startup_posture_chirho = ConfiguredServeStartupPostureChirho::RelayOnlyFollowerChirho;
        Ok(self)
    }
}

pub(super) struct ConfiguredLedgerHostServeOptionsChirho {
    pub(super) inflight_limit_chirho: usize,
    pub(super) auth_tokens_chirho: ServeAuthTokensChirho,
    pub(super) domain_routing_enabled_chirho: bool,
    pub(super) served_request_limits_chirho: ServedRequestAbuseLimitsChirho,
    pub(super) ledger_host_chirho: Option<Arc<LedgerHostProjectionReadPortChirho>>,
    pub(super) postgres_effect_chirho: Option<SharedLedgerHostPostgresEffectRuntimeChirho>,
    pub(super) monitor_wait_chirho: Arc<dyn LedgerMonitorCadenceWaitPortChirho>,
    pub(super) monitor_alarm_chirho: Arc<dyn LedgerConservationAlarmPortChirho>,
    pub(super) write_dispatch_chirho: Option<Arc<dyn ServedWriteDispatchPortChirho>>,
    pub(super) local_read_authority_chirho: Option<Arc<dyn ServedLocalReadAuthorityPortChirho>>,
    pub(super) write_destination_slot_chirho: Option<ServedWriteRelayDestinationSlotChirho>,
    pub(super) startup_posture_chirho: ConfiguredServeStartupPostureChirho,
}

impl LedgerMonitorRuntimeChirho {
    pub(super) fn spawn_chirho(self) -> LedgerMonitorTaskGuardChirho {
        let task_chirho = tokio::spawn(
            self.host_chirho
                .run_conservation_monitor_loop_chirho(self.wait_chirho, self.alarm_chirho),
        );
        LedgerMonitorTaskGuardChirho(task_chirho)
    }
}

pub(super) struct LedgerMonitorTaskGuardChirho(tokio::task::JoinHandle<()>);

impl Drop for LedgerMonitorTaskGuardChirho {
    fn drop(&mut self) {
        self.0.abort();
    }
}
