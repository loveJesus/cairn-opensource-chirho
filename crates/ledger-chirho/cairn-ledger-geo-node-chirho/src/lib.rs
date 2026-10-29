// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Production compositions for one exact GD7 geo-election node.
//!
//! The cluster transport always owns the sole election ticker. The held posture shares that exact
//! elector with a read-only coordinator. The winner posture waits for warm local leadership, opens
//! one resident authority actor around that same elector, and moves that actor into the existing
//! served effect runtime. Neither posture seeds election state, exposes reconciliation data,
//! compensates, adopts, or moves refs.
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-gd7-deposed-fork-reconciliation-design-chirho.md`.

pub mod a6_authority_composition_chirho;
mod held_evidence_transfer_chirho;
#[cfg(test)]
mod held_evidence_transfer_tests_chirho;
mod held_reconciliation_chirho;
mod held_view_transfer_chirho;
#[path = "tenant_placement_chirho/promotion_exit_chirho.rs"]
mod promotion_exit_chirho;
#[path = "tenant_placement_chirho/resident_startup_selector_chirho.rs"]
mod resident_startup_selector_chirho;
mod tenant_placement_chirho;
#[cfg(test)]
#[path = "tenant_placement_chirho/tests_chirho.rs"]
mod tenant_placement_tests_chirho;
#[cfg(feature = "testkind-roster-wide-admission-chirho")]
#[path = "tenant_placement_chirho/testkind_roster_wide_admission_chirho.rs"]
mod testkind_roster_wide_admission_chirho;
#[path = "tenant_placement_chirho/voter_startup_chirho.rs"]
mod voter_startup_chirho;
mod winner_fork_observation_chirho;
mod winner_view_transfer_chirho;
mod write_relay_composition_chirho;
pub mod writer_era_activation_chirho;

#[cfg(feature = "testkind-roster-wide-admission-chirho")]
pub use testkind_roster_wide_admission_chirho::serve_testkind_roster_wide_gd7_voter_geo_node_chirho;
pub use voter_startup_chirho::GeoVoterStartupOwnershipChirho;

use anyhow::{bail, Context, Result};
use axum::Router;
use cairn_config_chirho::config_chirho::{
    load_digest_bound_config_chirho, ConfigChirho, LedgerHostConfigChirho,
};
use cairn_ledger_host_chirho::{
    open_resident_gd7_held_coordinator_chirho, verify_host_ledger_config_custody_chirho,
    ResidentEffectJournalHandleChirho,
};
use cairn_serve_runtime_chirho::{
    open_shared_ledger_host_postgres_effect_runtime_with_resident_journal_chirho,
    serve_with_configured_ledger_host_chirho, ConfiguredLedgerHostRuntimePortsChirho,
    LedgerHostProjectionReadPortChirho, ServeAuthTokensChirho, ServedRequestAbuseLimitsChirho,
};
use cairn_tenant_chirho::tenant_chirho;
use cairn_writer_elector_http_chirho::cluster_file_config_chirho::{
    load_cluster_node_file_config_chirho, verify_cluster_node_file_config_custody_chirho,
};
use cairn_writer_elector_http_chirho::cluster_node_chirho::{
    ClusterNodeChirho, ClusterNodeConfigChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_for_root_chirho, ConsistencyGroupIdChirho,
};
use held_evidence_transfer_chirho::{
    drive_held_evidence_transfer_chirho, invoke_actor_owned_adoption_materialization_chirho,
};
use held_reconciliation_chirho::drive_held_reconciliation_chirho;
use held_view_transfer_chirho::drive_held_view_transfer_chirho;
use promotion_exit_chirho::PromotionExitWatchChirho;
use resident_startup_selector_chirho::{
    select_geo_resident_startup_chirho, GeoResidentStartupSelectionChirho,
};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use tenant_placement_chirho::{
    compose_tenant_migration_capacity_admission_chirho, verify_geo_held_startup_chirho,
    verify_geo_voter_startup_policy_chirho, GeoVoterPlacementAdmissionChirho,
    VerifiedGeoVoterStartupPolicyChirho,
};
use voter_startup_chirho::{
    configured_local_cluster_node_chirho, wait_for_known_warm_owner_chirho,
    GeoNonResidentVoterRoleChirho, GeoVoterStartupRoleChirho,
};
use winner_fork_observation_chirho::Gd7WinnerForkObservationServiceChirho;
use winner_view_transfer_chirho::{
    validate_winner_view_transfer_base_url_chirho, Gd7WinnerViewTransferServiceChirho,
};
use write_relay_composition_chirho::{
    compose_served_write_relay_chirho, validate_relay_lease_timing_chirho,
};
use writer_era_activation_chirho::{
    activate_fresh_writer_era_chirho, require_elected_writer_era_chirho,
};

use a6_authority_composition_chirho::{
    require_fault_tolerant_voter_floor_chirho, A6GeoResidentAuthorityCompositionChirho,
};

/// Serve one voting node through the exact election transport and app runtime.
///
/// A warm local owner installs the sole resident ledger actor before becoming relay-executable.
/// A follower installs no mutation runtime and can only relay governed requests to the current
/// owner. A later local promotion without resident activation fails closed instead of opening a
/// second authority implicitly.
///
/// This is the production entry point: it opens the sole resident actor through the refusing
/// default door (`default_resident_opener_chirho` -> the provider-less shared-elector opener), so a
/// production geo node can never complete a compensation. The reification into the winner-side
/// compensation-provider door lives only in `cairn-ledger-geo-node-testkind-chirho`, which passes
/// its own opener to [`serve_resident_gd7_voter_geo_node_with_resident_opener_chirho`].
pub fn serve_resident_gd7_voter_geo_node_chirho(
    cluster_config_path_chirho: &Path,
    ledger_config_path_chirho: &Path,
    expected_ledger_config_digest_chirho: &str,
    selected_root_chirho: &Path,
) -> Result<()> {
    serve_resident_gd7_voter_geo_node_with_resident_opener_chirho(
        cluster_config_path_chirho,
        ledger_config_path_chirho,
        expected_ledger_config_digest_chirho,
        selected_root_chirho,
        default_resident_opener_chirho,
    )
}

/// The production resident opener: the refusing-default door — a shared cluster elector and NO
/// compensation provider. This is the only opener a shipping geo node reaches, which is why the
/// shipping crate names zero compensation-provider door symbols (proved by Guard A,
/// `gd7_compensation_provider_door_has_no_shipping_binary_caller_chirho`).
fn default_resident_opener_chirho(
    authority_composition_chirho: &A6GeoResidentAuthorityCompositionChirho,
    selected_root_chirho: &Path,
    ledger_config_path_chirho: &Path,
    ledger_host_chirho: &LedgerHostConfigChirho,
) -> Result<ResidentEffectJournalHandleChirho> {
    authority_composition_chirho.open_required_mirrored_resident_effect_journal_chirho(
        selected_root_chirho,
        ledger_config_path_chirho,
        ledger_host_chirho,
    )
}

/// Serve the voter posture, injecting HOW the sole resident actor is opened.
///
/// The heavy winner startup — custody checks, election, writer-era activation, relay/observation
/// composition, and serving — lives here once. Only the single "open the resident actor" step is
/// injected. Production passes `default_resident_opener_chirho` (the provider-less door). The
/// distinct test-kind binary passes an opener that reaches the winner-side E-B
/// compensation-provider door, so the door SYMBOL lives only in that crate. This seam adds no
/// authority a production build can reach: the injected opener is the only way a provider door
/// enters this path, and naming a compensation-provider door in shipping source is exactly what
/// Guard A forbids.
pub fn serve_resident_gd7_voter_geo_node_with_resident_opener_chirho(
    cluster_config_path_chirho: &Path,
    ledger_config_path_chirho: &Path,
    expected_ledger_config_digest_chirho: &str,
    selected_root_chirho: &Path,
    open_resident_chirho: impl FnOnce(
        &A6GeoResidentAuthorityCompositionChirho,
        &Path,
        &Path,
        &LedgerHostConfigChirho,
    ) -> Result<ResidentEffectJournalHandleChirho>,
) -> Result<()> {
    serve_resident_gd7_voter_geo_node_with_resident_opener_and_local_owner_sidecar_chirho(
        cluster_config_path_chirho,
        ledger_config_path_chirho,
        expected_ledger_config_digest_chirho,
        selected_root_chirho,
        GeoVoterStartupOwnershipChirho::FirstKnownOwnerChirho,
        open_resident_chirho,
        |_selected_root_chirho, _host_chirho, _postgres_effect_chirho, _process_stop_chirho| {
            Ok(None)
        },
    )
}

/// Serve the voter posture with the same injected resident opener plus one optional local-owner
/// sidecar factory.
///
/// The factory is called only after the local winner's one resident actor has been composed into
/// the shared PostgreSQL effect runtime. It receives clones of that exact runtime and verified host;
/// it cannot open an elector, campaign, tick, or create a second writer. Production uses
/// [`serve_resident_gd7_voter_geo_node_with_resident_opener_chirho`], whose factory always returns
/// no sidecar.
/// The test-kind drill binary uses this seam for a filesystem-custodied Unix operator socket.
///
/// A sidecar must observe `process_stop_chirho`, set it if the sidecar fails, and return promptly
/// after it becomes true. The geo composition joins the sidecar before returning.
pub fn serve_resident_gd7_voter_geo_node_with_resident_opener_and_local_owner_sidecar_chirho(
    cluster_config_path_chirho: &Path,
    ledger_config_path_chirho: &Path,
    expected_ledger_config_digest_chirho: &str,
    selected_root_chirho: &Path,
    startup_ownership_chirho: GeoVoterStartupOwnershipChirho,
    open_resident_chirho: impl FnOnce(
        &A6GeoResidentAuthorityCompositionChirho,
        &Path,
        &Path,
        &LedgerHostConfigChirho,
    ) -> Result<ResidentEffectJournalHandleChirho>,
    start_local_owner_sidecar_chirho: impl FnOnce(
        &Path,
        Arc<LedgerHostProjectionReadPortChirho>,
        cairn_serve_runtime_chirho::SharedLedgerHostPostgresEffectRuntimeChirho,
        Arc<AtomicBool>,
    ) -> Result<Option<JoinHandle<Result<()>>>>,
) -> Result<()> {
    serve_resident_gd7_voter_geo_node_with_admission_chirho(
        cluster_config_path_chirho,
        ledger_config_path_chirho,
        expected_ledger_config_digest_chirho,
        selected_root_chirho,
        GeoVoterAdmissionPostureChirho::new_chirho(
            GeoVoterPlacementAdmissionChirho::ProductionRequiredChirho,
            startup_ownership_chirho,
        ),
        open_resident_chirho,
        start_local_owner_sidecar_chirho,
    )
}

pub(crate) struct GeoVoterAdmissionPostureChirho {
    placement_chirho: GeoVoterPlacementAdmissionChirho,
    startup_ownership_chirho: GeoVoterStartupOwnershipChirho,
}

impl GeoVoterAdmissionPostureChirho {
    pub(crate) fn new_chirho(
        placement_chirho: GeoVoterPlacementAdmissionChirho,
        startup_ownership_chirho: GeoVoterStartupOwnershipChirho,
    ) -> Self {
        Self {
            placement_chirho,
            startup_ownership_chirho,
        }
    }
}

fn serve_resident_gd7_voter_geo_node_with_admission_chirho(
    cluster_config_path_chirho: &Path,
    ledger_config_path_chirho: &Path,
    expected_ledger_config_digest_chirho: &str,
    selected_root_chirho: &Path,
    admission_posture_chirho: GeoVoterAdmissionPostureChirho,
    open_resident_chirho: impl FnOnce(
        &A6GeoResidentAuthorityCompositionChirho,
        &Path,
        &Path,
        &LedgerHostConfigChirho,
    ) -> Result<ResidentEffectJournalHandleChirho>,
    start_local_owner_sidecar_chirho: impl FnOnce(
        &Path,
        Arc<LedgerHostProjectionReadPortChirho>,
        cairn_serve_runtime_chirho::SharedLedgerHostPostgresEffectRuntimeChirho,
        Arc<AtomicBool>,
    ) -> Result<Option<JoinHandle<Result<()>>>>,
) -> Result<()> {
    let runtime_config_chirho = load_digest_bound_config_chirho(
        ledger_config_path_chirho,
        expected_ledger_config_digest_chirho,
    )
    .with_context(|| {
        format!(
            "load reviewed ledger config {}",
            ledger_config_path_chirho.display()
        )
    })?;
    verify_cluster_node_file_config_custody_chirho(
        selected_root_chirho,
        cluster_config_path_chirho,
    )
    .context("verify voter election config custody before reading it")?;
    let loaded_cluster_chirho = load_cluster_node_file_config_chirho(cluster_config_path_chirho)?;
    validate_resident_gd7_voter_cluster_preflight_chirho(&loaded_cluster_chirho.cluster_chirho)?;
    let parsed_cluster_config_blake3_chirho = loaded_cluster_chirho.config_blake3_chirho.clone();
    let writer_era_activation_authorization_chirho = loaded_cluster_chirho
        .writer_era_activation_authorization_chirho
        .clone();
    let group_chirho = loaded_cluster_chirho.cluster_chirho.group_chirho.clone();
    let local_node_chirho =
        configured_local_cluster_node_chirho(&loaded_cluster_chirho.cluster_chirho)?;
    let relay_sign_root_chirho = loaded_cluster_chirho
        .cluster_chirho
        .sign_root_chirho
        .clone();
    let relay_membership_chirho = loaded_cluster_chirho
        .cluster_chirho
        .membership_control_chirho
        .clone()
        .ok_or_else(|| anyhow::anyhow!("RelaySignedRosterCompositionUnavailableChirho"))?;
    let held_transfer_node_chirho =
        configured_gd7_held_transfer_recipient_chirho(&loaded_cluster_chirho.cluster_chirho)?;
    verify_resident_gd7_geo_group_binding_chirho(
        selected_root_chirho,
        &loaded_cluster_chirho.cluster_chirho.group_chirho,
    )?;
    let verified_placement_startup_chirho = verify_geo_voter_startup_policy_chirho(
        &loaded_cluster_chirho,
        selected_root_chirho,
        admission_posture_chirho.placement_chirho,
    )?;
    let resident_placement_chirho = verified_placement_startup_chirho.resident_placement_chirho();
    let tenant_migration_capacity_admission_chirho =
        compose_tenant_migration_capacity_admission_chirho(
            &loaded_cluster_chirho,
            resident_placement_chirho.as_ref().map(Arc::clone),
        )?;
    if admission_posture_chirho.startup_ownership_chirho
        == GeoVoterStartupOwnershipChirho::RecomposeLocalOwnerChirho
        && !verified_placement_startup_chirho.permits_local_resident_chirho()
    {
        bail!("LocalLeadershipTransferPlacementRefusedChirho");
    }

    verify_host_ledger_config_custody_chirho(selected_root_chirho, ledger_config_path_chirho)
        .context("verify ledger config custody before reading it")?;
    verify_resident_gd7_geo_config_root_binding_chirho(
        selected_root_chirho,
        &runtime_config_chirho,
    )?;
    let ledger_host_chirho = runtime_config_chirho
        .ledger_host_chirho
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("ledger host config is required for the winner geo node"))?;
    if ledger_host_chirho.postgres_effect_chirho.is_none() {
        bail!("winner geo node requires the configured served effect runtime");
    }

    let listen_addr_chirho = loaded_cluster_chirho.listen_addr_chirho;
    let verified_listen_addr_chirho = listen_addr_chirho
        .parse::<std::net::SocketAddr>()
        .context("parse numeric geo election and relay listener")?;
    let cluster_listener_chirho =
        TcpListener::bind(verified_listen_addr_chirho).with_context(|| {
            format!("bind geo election and relay transport at {listen_addr_chirho}")
        })?;
    let cluster_node_chirho =
        ClusterNodeChirho::open_existing_chirho(loaded_cluster_chirho.cluster_chirho)
            .context("open existing durable voter election node")?;
    let local_leadership_transfer_port_chirho = (admission_posture_chirho.startup_ownership_chirho
        == GeoVoterStartupOwnershipChirho::RecomposeLocalOwnerChirho)
        .then(|| cluster_node_chirho.local_leadership_transfer_port_chirho());
    let mut authority_composition_chirho =
        A6GeoResidentAuthorityCompositionChirho::from_cluster_node_chirho(&cluster_node_chirho)
            .context("select the deployable A6 geo authority composition")?;
    if let Some(capacity_admission_chirho) = tenant_migration_capacity_admission_chirho {
        authority_composition_chirho
            .install_capacity_admission_chirho(capacity_admission_chirho)
            .context("install capacity/load-driven tenant migration admission")?;
    }
    let tick_interval_chirho = cluster_node_chirho.tick_interval_chirho();
    let elector_chirho = Arc::clone(authority_composition_chirho.elector_chirho());
    let transfer_service_chirho = Gd7WinnerViewTransferServiceChirho::open_chirho(
        &relay_sign_root_chirho,
        &group_chirho,
        local_node_chirho.clone(),
        held_transfer_node_chirho.clone(),
        Arc::clone(&elector_chirho),
    )
    .context("compose private winner-view transfer surface")?;
    let observation_service_chirho = Gd7WinnerForkObservationServiceChirho::open_chirho(
        &relay_sign_root_chirho,
        &group_chirho,
        local_node_chirho.clone(),
        held_transfer_node_chirho,
        Arc::clone(&elector_chirho),
    )
    .context("compose private winner-fork observation surface")?;
    let relay_composition_chirho = compose_served_write_relay_chirho(
        &group_chirho,
        &relay_sign_root_chirho,
        &listen_addr_chirho,
        &local_node_chirho.0,
        &relay_membership_chirho,
        &cluster_node_chirho,
    )
    .context("compose signed-mesh served-write relay")?;
    let mirror_router_chirho = authority_composition_chirho
        .install_configured_append_mirror_chirho(
            selected_root_chirho,
            ledger_host_chirho,
            &relay_sign_root_chirho,
            &local_node_chirho.0,
            resident_placement_chirho,
            relay_composition_chirho
                .mirror_peer_endpoints_chirho
                .clone(),
        )?;
    let stop_chirho = Arc::new(AtomicBool::new(false));
    install_shared_stop_handler_chirho(&stop_chirho)?;
    let mut composed_router_chirho = transfer_service_chirho
        .router_chirho()
        .merge(observation_service_chirho.router_chirho())
        .merge(relay_composition_chirho.router_chirho.clone());
    if let Some(mirror_router_chirho) = mirror_router_chirho {
        composed_router_chirho = composed_router_chirho.merge(mirror_router_chirho);
    }
    let cluster_thread_chirho = start_cluster_transport_chirho(
        cluster_node_chirho,
        cluster_listener_chirho,
        &stop_chirho,
        Some(composed_router_chirho),
    )?;

    let startup_result_chirho = wait_for_known_warm_owner_chirho(
        &elector_chirho,
        &local_node_chirho,
        &verified_placement_startup_chirho,
        &stop_chirho,
        tick_interval_chirho,
        admission_posture_chirho.startup_ownership_chirho,
        local_leadership_transfer_port_chirho.as_ref(),
    )
    .and_then(|role_chirho| {
        let selection_chirho = select_geo_resident_startup_chirho(role_chirho, || {
            open_resident_chirho(
                &authority_composition_chirho,
                selected_root_chirho,
                ledger_config_path_chirho,
                ledger_host_chirho,
            )
            .context("open sole resident actor around the transport elector")
        })?;
        match selection_chirho {
            GeoResidentStartupSelectionChirho::LocalWarmOwnerChirho(resident_chirho) => {
            match cairn_writer_head_chirho::writer_head_chirho::writer_authority_era_chirho(
                selected_root_chirho,
            )? {
                cairn_writer_head_chirho::writer_head_chirho::WriterAuthorityEraChirho::LocalChirho => {
                    let authorization_path_chirho =
                        writer_era_activation_authorization_chirho.as_deref().ok_or_else(|| {
                            anyhow::anyhow!(
                                "GeoWriterEraActivationAuthorizationPathMissingChirho"
                            )
                        })?;
                    let activated_epoch_chirho = activate_fresh_writer_era_chirho(
                        selected_root_chirho,
                        &group_chirho,
                        &local_node_chirho.0,
                        &relay_membership_chirho
                            .roster_authority_chirho
                            .roster_head_path_chirho,
                        &relay_membership_chirho
                            .roster_authority_chirho
                            .operator_pubkey_hex_chirho,
                        &parsed_cluster_config_blake3_chirho,
                        authorization_path_chirho,
                        resident_chirho.head_transition_authority_chirho(),
                    )?;
                    eprintln!(
                        "geo writer era activated under elected fence epoch {activated_epoch_chirho}"
                    );
                }
                cairn_writer_head_chirho::writer_head_chirho::WriterAuthorityEraChirho::ElectedChirho => {}
            }
            require_elected_writer_era_chirho(selected_root_chirho)?;
            transfer_service_chirho
                .install_winner_handles_chirho(
                    resident_chirho
                        .gd7_winner_evidence_handle_chirho()
                        .context("derive restricted transfer handle from the resident actor")?,
                    resident_chirho
                        .gd7_winner_handoff_handle_chirho()
                        .context("derive restricted handoff handle from the resident actor")?,
                    resident_chirho
                        .gd7_winner_adoption_evidence_handle_chirho()
                        .context(
                            "derive accepted-barrier evidence handle from the resident actor",
                        )?,
                )
                .context("install resident actor handles into winner-view transfer surface")?;
            observation_service_chirho
                .install_winner_handle_chirho(
                    resident_chirho
                        .gd7_winner_evidence_handle_chirho()
                        .context("derive restricted observation handle from resident actor")?,
                )
                .context("install resident actor into winner-fork observation surface")?;
            relay_composition_chirho.mark_local_authority_ready_chirho();
            Ok((
                GeoVoterStartupRoleChirho::LocalWarmOwnerChirho,
                Some(resident_chirho),
            ))
            }
            GeoResidentStartupSelectionChirho::NonResidentChirho(nonresident_role_chirho) => {
                // Every nonresident process must already have crossed the one-way elected-era latch.
                // In particular, retirement cannot become an activation door for a fresh root.
                require_elected_writer_era_chirho(selected_root_chirho)?;
                Ok((
                    GeoVoterStartupRoleChirho::NonResidentChirho(nonresident_role_chirho),
                    None,
                ))
            }
        }
    });
    let (startup_role_chirho, resident_chirho) = match startup_result_chirho {
        Ok(startup_chirho) => startup_chirho,
        Err(error_chirho) => {
            stop_chirho.store(true, Ordering::Release);
            join_cluster_transport_chirho(cluster_thread_chirho)?;
            return Err(error_chirho);
        }
    };
    let effective_ledger_host_chirho = resident_chirho
        .as_ref()
        .map(|resident_chirho| resident_chirho.effective_ledger_config_chirho().clone())
        .unwrap_or_else(|| ledger_host_chirho.clone());

    let mut local_owner_sidecar_thread_chirho = None;
    let mut promotion_exit_watch_chirho = None;
    let serve_result_chirho = (|| -> Result<()> {
        let host_chirho = Arc::new(
            LedgerHostProjectionReadPortChirho::open_existing_chirho(
                selected_root_chirho,
                ledger_config_path_chirho,
                &effective_ledger_host_chirho,
            )
            .context("open verified winner projection host")?,
        );
        let postgres_effect_chirho = resident_chirho
            .map(|resident_chirho| {
                open_shared_ledger_host_postgres_effect_runtime_with_resident_journal_chirho(
                    selected_root_chirho,
                    Arc::clone(&host_chirho),
                    &effective_ledger_host_chirho,
                    resident_chirho,
                )
                .context("compose served effect runtime around the sole resident actor")
            })
            .transpose()?;
        if let Some(postgres_effect_chirho) = postgres_effect_chirho.as_ref() {
            local_owner_sidecar_thread_chirho = start_local_owner_sidecar_chirho(
                selected_root_chirho,
                Arc::clone(&host_chirho),
                postgres_effect_chirho.clone(),
                Arc::clone(&stop_chirho),
            )?;
        }
        let runtime_ports_chirho = ConfiguredLedgerHostRuntimePortsChirho::composed_chirho(
            host_chirho,
            postgres_effect_chirho,
        )
        .with_process_stop_chirho(Arc::clone(&stop_chirho))
        .with_served_write_relay_chirho(
            Arc::clone(&relay_composition_chirho.dispatch_chirho),
            Arc::clone(&relay_composition_chirho.local_read_authority_chirho),
            relay_composition_chirho.destination_slot_chirho.clone(),
        );
        let runtime_ports_chirho = match startup_role_chirho {
            GeoVoterStartupRoleChirho::LocalWarmOwnerChirho => runtime_ports_chirho,
            GeoVoterStartupRoleChirho::NonResidentChirho(_) => {
                runtime_ports_chirho.with_relay_only_follower_startup_chirho()?
            }
        };
        let served_request_limits_chirho = ServedRequestAbuseLimitsChirho {
            window_ms_chirho: runtime_config_chirho.served_request_window_ms_chirho,
            actor_max_requests_chirho: runtime_config_chirho.served_request_actor_max_chirho,
            actor_max_body_bytes_chirho: runtime_config_chirho
                .served_request_actor_body_bytes_chirho,
            global_max_requests_chirho: runtime_config_chirho.served_request_global_max_chirho,
            global_max_body_bytes_chirho: runtime_config_chirho
                .served_request_global_body_bytes_chirho,
            actor_bucket_cap_chirho: runtime_config_chirho.served_request_actor_bucket_cap_chirho,
            sign_in_principal_successes_per_hour_chirho: runtime_config_chirho
                .sign_in_principal_successes_per_hour_chirho,
            sign_in_source_successes_per_hour_chirho: runtime_config_chirho
                .sign_in_source_successes_per_hour_chirho,
            sign_in_source_failures_per_window_chirho: runtime_config_chirho
                .sign_in_source_failures_per_window_chirho,
        };
        let role_label_chirho = startup_role_chirho.label_chirho();
        eprintln!(
            "geo ledger node ({role_label_chirho}) serving election and relay transport on {listen_addr_chirho} and app HTTP on 127.0.0.1:{}",
            runtime_config_chirho.port_chirho
        );
        promotion_exit_watch_chirho = Some(PromotionExitWatchChirho::start_for_role_chirho(
            startup_role_chirho,
            Arc::clone(&elector_chirho),
            local_node_chirho.clone(),
            tick_interval_chirho,
            Arc::clone(&stop_chirho),
        )?);
        let runtime_chirho = tokio::runtime::Runtime::new().context("build geo app runtime")?;
        runtime_chirho.block_on(serve_with_configured_ledger_host_chirho(
            selected_root_chirho,
            runtime_config_chirho.port_chirho,
            runtime_config_chirho.inflight_limit_chirho,
            ServeAuthTokensChirho::new_chirho(
                runtime_config_chirho.publish_token_chirho.clone(),
                runtime_config_chirho.registration_token_chirho.clone(),
            ),
            runtime_config_chirho.domain_routing_enabled_chirho,
            served_request_limits_chirho,
            runtime_ports_chirho,
        ))
    })();
    stop_chirho.store(true, Ordering::Release);
    let sidecar_result_chirho = local_owner_sidecar_thread_chirho
        .map(|thread_chirho| {
            thread_chirho
                .join()
                .map_err(|_panic_chirho| anyhow::anyhow!("local-owner sidecar panicked"))?
        })
        .transpose();
    let cluster_result_chirho = join_cluster_transport_chirho(cluster_thread_chirho);
    promotion_exit_watch_chirho
        .map(PromotionExitWatchChirho::finish_chirho)
        .transpose()?;
    serve_result_chirho?;
    sidecar_result_chirho?;
    cluster_result_chirho
}

fn validate_resident_gd7_voter_cluster_preflight_chirho(
    cluster_chirho: &ClusterNodeConfigChirho,
) -> Result<()> {
    validate_relay_lease_timing_chirho(cluster_chirho.tick_interval_chirho).map_err(
        |error_chirho| {
            anyhow::anyhow!(
                "validate served-write lease timing before opening runtime authority state: \
                 {error_chirho}"
            )
        },
    )?;
    // Three voters is the structural fault-tolerant code floor. The B5/genesis deployment law is
    // separately the full seven-voter fleet including every Ruth node; this floor does not weaken it.
    require_fault_tolerant_voter_floor_chirho(cluster_chirho.voters_chirho.len())?;
    verify_resident_gd7_voter_cluster_posture_chirho(cluster_chirho)
}

fn verify_resident_gd7_voter_cluster_posture_chirho(
    cluster_chirho: &ClusterNodeConfigChirho,
) -> Result<()> {
    let local_voter_count_chirho = cluster_chirho
        .voters_chirho
        .iter()
        .filter(|(raft_id_chirho, _node_chirho)| {
            *raft_id_chirho == cluster_chirho.local_raft_id_chirho
        })
        .count();
    if local_voter_count_chirho != 1 {
        bail!("served GD7 node must appear exactly once in the voter roster");
    }
    if cluster_chirho
        .learners_chirho
        .iter()
        .any(|(raft_id_chirho, _node_chirho)| {
            *raft_id_chirho == cluster_chirho.local_raft_id_chirho
        })
    {
        bail!("served GD7 node must not also appear in the learner roster");
    }
    configured_gd7_held_transfer_recipient_chirho(cluster_chirho)?;
    Ok(())
}

fn configured_gd7_held_transfer_recipient_chirho(
    cluster_chirho: &ClusterNodeConfigChirho,
) -> Result<cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho> {
    let [(_raft_id_chirho, held_node_chirho)] = cluster_chirho.learners_chirho.as_slice() else {
        bail!("winner GD7 transfer requires exactly one configured held learner");
    };
    Ok(held_node_chirho.clone())
}

fn install_shared_stop_handler_chirho(stop_chirho: &Arc<AtomicBool>) -> Result<()> {
    let signal_stop_chirho = Arc::clone(stop_chirho);
    ctrlc::set_handler(move || signal_stop_chirho.store(true, Ordering::Release))
        .context("install geo node shutdown handler")
}

fn start_cluster_transport_chirho(
    cluster_node_chirho: ClusterNodeChirho,
    listener_chirho: TcpListener,
    stop_chirho: &Arc<AtomicBool>,
    additional_router_chirho: Option<Router>,
) -> Result<JoinHandle<Result<()>>> {
    let transport_stop_chirho = Arc::clone(stop_chirho);
    std::thread::Builder::new()
        .name("gd7-election-transport-chirho".to_owned())
        .spawn(move || {
            let result_chirho = match additional_router_chirho {
                Some(additional_router_chirho) => cluster_node_chirho
                    .serve_blocking_with_additional_router_chirho(
                        listener_chirho,
                        Arc::clone(&transport_stop_chirho),
                        additional_router_chirho,
                    ),
                None => cluster_node_chirho
                    .serve_blocking_chirho(listener_chirho, Arc::clone(&transport_stop_chirho)),
            };
            transport_stop_chirho.store(true, Ordering::Release);
            result_chirho
        })
        .context("start winner election transport")
}

fn join_cluster_transport_chirho(cluster_thread_chirho: JoinHandle<Result<()>>) -> Result<()> {
    cluster_thread_chirho
        .join()
        .map_err(|_panic_chirho| anyhow::anyhow!("winner election transport panicked"))?
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeldGeoRecoveryRouteChirho {
    DrivePlanSealedProducersChirho,
    ResumeAdoptedMonitorChirho,
}

fn held_geo_recovery_route_chirho(
    phase_chirho: Option<
        cairn_ledger_host_chirho::reconciliation_chirho::Gd7ReconciliationPhaseChirho,
    >,
) -> HeldGeoRecoveryRouteChirho {
    if phase_chirho
        == Some(
            cairn_ledger_host_chirho::reconciliation_chirho::Gd7ReconciliationPhaseChirho::AdoptedHeldChirho,
        )
    {
        HeldGeoRecoveryRouteChirho::ResumeAdoptedMonitorChirho
    } else {
        HeldGeoRecoveryRouteChirho::DrivePlanSealedProducersChirho
    }
}

/// Reopen one existing election node and its frozen held journal under the writer lock, then serve
/// the election transport. Schema v4 authenticates its remote winner only after the recovered
/// transport is running; no winner evidence is imported before that exact bootstrap revalidates.
pub fn serve_resident_gd7_held_geo_node_chirho(
    cluster_config_path_chirho: &Path,
    ledger_config_path_chirho: &Path,
    expected_ledger_config_digest_chirho: &str,
    selected_root_chirho: &Path,
) -> Result<()> {
    let runtime_config_chirho = load_digest_bound_config_chirho(
        ledger_config_path_chirho,
        expected_ledger_config_digest_chirho,
    )
    .with_context(|| {
        format!(
            "load reviewed ledger config {}",
            ledger_config_path_chirho.display()
        )
    })?;
    verify_cluster_node_file_config_custody_chirho(
        selected_root_chirho,
        cluster_config_path_chirho,
    )
    .context("verify held election config custody before reading it")?;
    let loaded_cluster_chirho = load_cluster_node_file_config_chirho(cluster_config_path_chirho)?;
    verify_resident_gd7_held_cluster_posture_chirho(&loaded_cluster_chirho.cluster_chirho)?;
    verify_resident_gd7_geo_group_binding_chirho(
        selected_root_chirho,
        &loaded_cluster_chirho.cluster_chirho.group_chirho,
    )?;
    verify_geo_held_startup_chirho(&loaded_cluster_chirho, selected_root_chirho)?;

    verify_host_ledger_config_custody_chirho(selected_root_chirho, ledger_config_path_chirho)
        .context("verify ledger config custody before reading it")?;
    verify_resident_gd7_geo_config_root_binding_chirho(
        selected_root_chirho,
        &runtime_config_chirho,
    )?;
    let ledger_host_chirho = runtime_config_chirho
        .ledger_host_chirho
        .ok_or_else(|| anyhow::anyhow!("ledger host config is required for the held geo node"))?;

    let listen_addr_chirho = loaded_cluster_chirho.listen_addr_chirho;
    let held_group_chirho = loaded_cluster_chirho.cluster_chirho.group_chirho.clone();
    let configured_peers_chirho = loaded_cluster_chirho.cluster_chirho.peers_chirho.clone();
    let cluster_node_chirho =
        ClusterNodeChirho::open_existing_chirho(loaded_cluster_chirho.cluster_chirho)
            .context("open existing durable geo election node")?;
    let tick_interval_chirho = cluster_node_chirho.tick_interval_chirho();
    let elector_chirho = Arc::clone(cluster_node_chirho.elector_chirho());
    let mut held_coordinator_chirho = open_resident_gd7_held_coordinator_chirho(
        selected_root_chirho,
        ledger_config_path_chirho,
        &ledger_host_chirho,
        Arc::clone(&elector_chirho),
    )
    .context("open held GD7 coordinator under the retained writer lock")?;

    let listener_chirho = TcpListener::bind(&listen_addr_chirho)
        .with_context(|| format!("bind held geo node at {listen_addr_chirho}"))?;
    let stop_chirho = Arc::new(AtomicBool::new(false));
    let signal_stop_chirho = Arc::clone(&stop_chirho);
    ctrlc::set_handler(move || signal_stop_chirho.store(true, Ordering::Relaxed))
        .context("install held geo node shutdown handler")?;
    let cluster_thread_chirho =
        start_cluster_transport_chirho(cluster_node_chirho, listener_chirho, &stop_chirho, None)
            .context("start held election transport")?;
    eprintln!(
        "held geo ledger node serving election transport on {listen_addr_chirho} while reconciling its frozen fork"
    );
    let startup_phase_result_chirho = (|| {
        let bootstrap_chirho = held_coordinator_chirho
            .bootstrap_chirho()
            .context("authenticate held GD7 bootstrap before recovery routing")?;
        match bootstrap_chirho.active_checkpoint_ref_chirho {
            Some(_checkpoint_ref_chirho) => held_coordinator_chirho
                .inspect_chirho()
                .map(|snapshot_chirho| Some(snapshot_chirho.phase_chirho))
                .context("inspect held GD7 phase before recovery routing"),
            None => Ok(None),
        }
    })();
    let startup_phase_chirho = match startup_phase_result_chirho {
        Ok(startup_phase_chirho) => startup_phase_chirho,
        Err(error_chirho) => {
            stop_chirho.store(true, Ordering::Release);
            let serve_result_chirho = join_cluster_transport_chirho(cluster_thread_chirho);
            let close_result_chirho = held_coordinator_chirho.close_chirho();
            serve_result_chirho?;
            close_result_chirho?;
            return Err(error_chirho);
        }
    };
    if held_geo_recovery_route_chirho(startup_phase_chirho)
        == HeldGeoRecoveryRouteChirho::ResumeAdoptedMonitorChirho
    {
        let mut held_monitor_chirho = match held_coordinator_chirho
            .start_fail_stop_monitor_chirho(Arc::clone(&stop_chirho), tick_interval_chirho)
            .context("start held GD7 fail-stop monitor after adopted restart verification")
        {
            Ok(held_monitor_chirho) => held_monitor_chirho,
            Err(error_chirho) => {
                stop_chirho.store(true, Ordering::Release);
                let serve_result_chirho = join_cluster_transport_chirho(cluster_thread_chirho);
                let close_result_chirho = held_coordinator_chirho.close_chirho();
                serve_result_chirho?;
                close_result_chirho?;
                return Err(error_chirho);
            }
        };
        eprintln!(
            "held GD7 adoption selector restart-reverified; group hold remains active and no write or application ref is enabled"
        );
        let serve_result_chirho = join_cluster_transport_chirho(cluster_thread_chirho);
        let monitor_result_chirho = held_monitor_chirho.close_chirho();
        let close_result_chirho = held_coordinator_chirho.close_chirho();
        monitor_result_chirho.context("held GD7 fail-stop monitor refused adopted serving")?;
        serve_result_chirho?;
        return close_result_chirho;
    }
    let reconciliation_result_chirho = (|| -> Result<String> {
        let bootstrap_chirho = held_coordinator_chirho
            .bootstrap_chirho()
            .context("authenticate held GD7 bootstrap after transport recovery")?;
        let winner_node_chirho = cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho(
            bootstrap_chirho.winner_node_chirho,
        );
        let winner_base_url_chirho = configured_peer_base_url_for_node_chirho(
            &elector_chirho,
            &configured_peers_chirho,
            &winner_node_chirho,
        )
        .context("resolve authenticated winner reconciliation endpoint")?;
        let sealed_plan_chirho = drive_held_reconciliation_chirho(
            selected_root_chirho,
            &winner_base_url_chirho,
            &held_coordinator_chirho,
            &stop_chirho,
        )?;
        eprintln!(
            "held GD7 reconciliation sealed and reverified at checkpoint {} without adoption or write enablement",
            sealed_plan_chirho.checkpoint_ref_chirho
        );
        Ok(winner_base_url_chirho)
    })();
    let winner_base_url_chirho = match reconciliation_result_chirho {
        Ok(winner_base_url_chirho) => winner_base_url_chirho,
        Err(error_chirho) => {
            stop_chirho.store(true, Ordering::Release);
            let serve_result_chirho = join_cluster_transport_chirho(cluster_thread_chirho);
            let close_result_chirho = held_coordinator_chirho.close_chirho();
            serve_result_chirho?;
            close_result_chirho?;
            return Err(error_chirho);
        }
    };
    let mut held_monitor_chirho = match held_coordinator_chirho
        .start_fail_stop_monitor_chirho(Arc::clone(&stop_chirho), tick_interval_chirho)
        .context("start held GD7 fail-stop monitor after plan sealing")
    {
        Ok(held_monitor_chirho) => held_monitor_chirho,
        Err(error_chirho) => {
            stop_chirho.store(true, Ordering::Release);
            let serve_result_chirho = join_cluster_transport_chirho(cluster_thread_chirho);
            let close_result_chirho = held_coordinator_chirho.close_chirho();
            serve_result_chirho?;
            close_result_chirho?;
            return Err(error_chirho);
        }
    };
    let transfer_result_chirho = drive_held_view_transfer_chirho(
        selected_root_chirho,
        &held_group_chirho,
        &winner_base_url_chirho,
        &held_coordinator_chirho,
        &elector_chirho,
        &stop_chirho,
    );
    if let Ok(active_chirho) = &transfer_result_chirho {
        if active_chirho.checkpoint_chirho.phase_chirho
            == cairn_ledger_host_chirho::reconciliation_chirho::Gd7HeldViewTransferPhaseChirho::CompleteChirho
        {
            eprintln!(
                "held GD7 winner view received at checkpoint {} without adoption or write enablement",
                active_chirho.checkpoint_ref_chirho
            );
        }
    } else {
        stop_chirho.store(true, Ordering::Release);
    }
    let evidence_transfer_result_chirho = transfer_result_chirho
        .as_ref()
        .map_err(|error_chirho| {
            anyhow::anyhow!(
                "held winner-view transfer failed before adoption evidence: {error_chirho}"
            )
        })
        .and_then(|completed_view_chirho| {
            drive_held_evidence_transfer_chirho(
                selected_root_chirho,
                &ledger_host_chirho,
                &winner_base_url_chirho,
                &held_coordinator_chirho,
                &elector_chirho,
                completed_view_chirho,
                &stop_chirho,
            )
        });
    if let Ok(active_chirho) = &evidence_transfer_result_chirho {
        if active_chirho.checkpoint_chirho.phase_chirho
            == cairn_ledger_host_chirho::reconciliation_chirho::Gd7HeldEvidenceTransferPhaseChirho::CompleteChirho
        {
            eprintln!(
                "held GD7 winner history and fork baseline independently reverified at checkpoint {} without adoption or write enablement",
                active_chirho.checkpoint_ref_chirho
            );
        }
    } else {
        stop_chirho.store(true, Ordering::Release);
    }
    let adoption_materialization_result_chirho = evidence_transfer_result_chirho
        .as_ref()
        .map_err(|error_chirho| {
            anyhow::anyhow!("held adoption evidence failed before materialization: {error_chirho}")
        })
        .and_then(|active_chirho| {
            invoke_actor_owned_adoption_materialization_chirho(
                &active_chirho.checkpoint_chirho.identity_chirho,
                &active_chirho.checkpoint_ref_chirho,
                |request_chirho| {
                    held_coordinator_chirho.prepare_adoption_materialization_chirho(request_chirho)
                },
            )
        });
    if let Ok(prepared_chirho) = &adoption_materialization_result_chirho {
        eprintln!(
            "held GD7 ordinary-journal adoption candidate materialized at {} without phase change or write enablement",
            prepared_chirho.input_binding_digest_chirho()
        );
    } else {
        stop_chirho.store(true, Ordering::Release);
    }
    let adoption_commit_result_chirho = adoption_materialization_result_chirho
        .as_ref()
        .map_err(|error_chirho| {
            anyhow::anyhow!("held adoption candidate failed before selector commit: {error_chirho}")
        })
        .and_then(|prepared_chirho| {
            held_coordinator_chirho
                .commit_adoption_chirho(prepared_chirho.clone())
                .context("commit and restart-reverify held GD7 adoption selector")
        });
    match &adoption_commit_result_chirho {
        Ok(cairn_ledger_host_chirho::ResidentGd7HeldAdoptionCommitOutcomeChirho::CommittedChirho(
            snapshot_chirho,
        )) => {
            eprintln!(
                "held GD7 adoption selector committed at checkpoint {} while the group hold continues to refuse writes",
                snapshot_chirho.checkpoint_ref_chirho()
            );
        }
        Ok(cairn_ledger_host_chirho::ResidentGd7HeldAdoptionCommitOutcomeChirho::AlreadyAdoptedExactChirho(
            snapshot_chirho,
        )) => {
            eprintln!(
                "held GD7 adoption selector already committed exactly at checkpoint {} and restart-reverified",
                snapshot_chirho.checkpoint_ref_chirho()
            );
        }
        Err(_error_chirho) => stop_chirho.store(true, Ordering::Release),
    }
    let serve_result_chirho = join_cluster_transport_chirho(cluster_thread_chirho);
    let monitor_result_chirho = held_monitor_chirho.close_chirho();
    let close_result_chirho = held_coordinator_chirho.close_chirho();
    transfer_result_chirho?;
    evidence_transfer_result_chirho?;
    adoption_materialization_result_chirho?;
    adoption_commit_result_chirho?;
    monitor_result_chirho.context("held GD7 fail-stop monitor refused continued serving")?;
    serve_result_chirho?;
    close_result_chirho
}

fn configured_peer_base_url_for_node_chirho(
    elector_chirho: &cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho,
    configured_peers_chirho: &[(u64, String)],
    expected_node_chirho: &cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho,
) -> Result<String> {
    let matching_raft_ids_chirho = elector_chirho
        .authenticated_members_chirho()
        .iter()
        .filter(|(_raft_id_chirho, node_chirho)| node_chirho == expected_node_chirho)
        .map(|(raft_id_chirho, _node_chirho)| *raft_id_chirho)
        .collect::<Vec<_>>();
    let [winner_raft_id_chirho] = matching_raft_ids_chirho.as_slice() else {
        bail!("winner node must appear exactly once in the authenticated election roster");
    };
    let matching_urls_chirho = configured_peers_chirho
        .iter()
        .filter(|(raft_id_chirho, _url_chirho)| raft_id_chirho == winner_raft_id_chirho)
        .map(|(_raft_id_chirho, url_chirho)| url_chirho.clone())
        .collect::<Vec<_>>();
    match matching_urls_chirho.as_slice() {
        [winner_url_chirho] => {
            validate_winner_view_transfer_base_url_chirho(winner_url_chirho)?;
            Ok(winner_url_chirho.clone())
        }
        _ => bail!("winner node must map to exactly one custody-checked peer URL"),
    }
}

fn verify_resident_gd7_held_cluster_posture_chirho(
    cluster_chirho: &ClusterNodeConfigChirho,
) -> Result<()> {
    if cluster_chirho.membership_control_chirho.is_some() {
        bail!("held GD7 node must not expose membership-control routes");
    }
    if cluster_chirho
        .voters_chirho
        .iter()
        .any(|(raft_id_chirho, _node_chirho)| {
            *raft_id_chirho == cluster_chirho.local_raft_id_chirho
        })
    {
        bail!("held GD7 node must be a non-voting learner");
    }
    let local_learner_count_chirho = cluster_chirho
        .learners_chirho
        .iter()
        .filter(|(raft_id_chirho, _node_chirho)| {
            *raft_id_chirho == cluster_chirho.local_raft_id_chirho
        })
        .count();
    if local_learner_count_chirho != 1 {
        bail!("held GD7 node must appear exactly once in the learner roster");
    }
    Ok(())
}

fn verify_resident_gd7_geo_group_binding_chirho(
    selected_root_chirho: &Path,
    configured_group_chirho: &ConsistencyGroupIdChirho,
) -> Result<()> {
    let actual_group_chirho = consistency_group_for_root_chirho(selected_root_chirho)
        .context("derive selected-root consistency group")?;
    if actual_group_chirho != *configured_group_chirho {
        bail!("selected ledger root and election config name different consistency groups");
    }
    Ok(())
}

fn verify_resident_gd7_geo_config_root_binding_chirho(
    selected_root_chirho: &Path,
    runtime_config_chirho: &ConfigChirho,
) -> Result<()> {
    let configured_root_chirho = PathBuf::from(&runtime_config_chirho.root_chirho);
    let effective_root_chirho = match runtime_config_chirho
        .tenant_chirho
        .as_deref()
        .filter(|tenant_chirho| !tenant_chirho.trim().is_empty())
    {
        Some(tenant_id_chirho) => {
            tenant_chirho::tenant_root_chirho(&configured_root_chirho, tenant_id_chirho)
                .context("derive configured tenant root")?
        }
        None => configured_root_chirho,
    };
    let canonical_selected_chirho = selected_root_chirho
        .canonicalize()
        .context("canonicalize selected ledger root")?;
    let canonical_configured_chirho = effective_root_chirho
        .canonicalize()
        .context("canonicalize configured ledger root")?;
    if canonical_selected_chirho != canonical_configured_chirho {
        bail!("selected ledger root differs from the configured effective runtime root");
    }
    Ok(())
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use cairn_writer_elector_http_chirho::cluster_file_config_chirho::parse_cluster_node_file_config_chirho;
    use cairn_writer_elector_http_chirho::membership_control_chirho::{
        MembershipControlConfigChirho, MembershipTargetAuthorityChirho,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_root_chirho(label_chirho: &str) -> PathBuf {
        let nonce_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "cairn-ledger-geo-node-{label_chirho}-{}-{nonce_chirho}-chirho",
            std::process::id()
        ))
    }

    #[test]
    fn selected_root_must_exactly_match_election_group_chirho() {
        let root_chirho = test_root_chirho("group-binding");
        std::fs::create_dir_all(&root_chirho).unwrap();
        let actual_group_chirho = consistency_group_for_root_chirho(&root_chirho).unwrap();
        verify_resident_gd7_geo_group_binding_chirho(&root_chirho, &actual_group_chirho).unwrap();

        let different_group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
            canonical_root_chirho: "/different-cairn-root-chirho".to_owned(),
        };
        let error_chirho =
            verify_resident_gd7_geo_group_binding_chirho(&root_chirho, &different_group_chirho)
                .unwrap_err();
        assert!(error_chirho
            .to_string()
            .contains("different consistency groups"));

        std::fs::remove_dir_all(root_chirho).unwrap();
    }

    #[test]
    fn selected_root_must_match_effective_runtime_root_chirho() {
        let root_chirho = test_root_chirho("config-binding");
        let other_root_chirho = test_root_chirho("config-binding-other");
        std::fs::create_dir_all(&root_chirho).unwrap();
        std::fs::create_dir_all(&other_root_chirho).unwrap();
        let runtime_config_chirho = ConfigChirho {
            root_chirho: root_chirho.to_string_lossy().into_owned(),
            ..ConfigChirho::default()
        };

        verify_resident_gd7_geo_config_root_binding_chirho(&root_chirho, &runtime_config_chirho)
            .unwrap();
        let error_chirho = verify_resident_gd7_geo_config_root_binding_chirho(
            &other_root_chirho,
            &runtime_config_chirho,
        )
        .unwrap_err();
        assert!(error_chirho
            .to_string()
            .contains("differs from the configured effective runtime root"));

        std::fs::remove_dir_all(root_chirho).unwrap();
        std::fs::remove_dir_all(other_root_chirho).unwrap();
    }

    /// Drift-guard: 6.5-b's `cairn-drill-root-layout-chirho` recomposes these two root bindings from
    /// the same public primitives so its no-host validator asserts the exact predicate this node
    /// runs. This drives BOTH the geo originals and the recomposed copies over one fixture battery
    /// and asserts an identical accept/reject verdict on every case — so a future edit to either geo
    /// binding that silently diverges from the recomposed copy fails here. The dev-only edge runs
    /// geo-node -> layout (the layout crate never depends on the geo node), so there is no cycle.
    #[test]
    fn recomposed_drill_bindings_match_the_geo_originals_chirho() {
        use cairn_drill_root_layout_chirho::{
            check_config_root_binding_chirho, check_group_binding_chirho,
        };

        let base_chirho = test_root_chirho("drift-guard");
        std::fs::create_dir_all(&base_chirho).unwrap();

        // ---- config-root binding battery ----
        let platform_root_chirho = base_chirho.join("platform-root-chirho");
        std::fs::create_dir_all(&platform_root_chirho).unwrap();
        let tenant_root_chirho =
            tenant_chirho::tenant_root_chirho(&platform_root_chirho, "acme").unwrap();
        std::fs::create_dir_all(&tenant_root_chirho).unwrap();
        let other_root_chirho = base_chirho.join("other-root-chirho");
        std::fs::create_dir_all(&other_root_chirho).unwrap();
        let symlink_target_chirho = base_chirho.join("symlink-target-chirho");
        std::fs::create_dir_all(&symlink_target_chirho).unwrap();
        let symlink_selected_chirho = base_chirho.join("symlink-selected-chirho");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&symlink_target_chirho, &symlink_selected_chirho).unwrap();

        let platform_config_chirho = |root_chirho: &Path| ConfigChirho {
            root_chirho: root_chirho.to_string_lossy().into_owned(),
            ..ConfigChirho::default()
        };
        let tenant_config_chirho = |root_chirho: &Path, tenant_chirho: &str| ConfigChirho {
            root_chirho: root_chirho.to_string_lossy().into_owned(),
            tenant_chirho: Some(tenant_chirho.to_owned()),
            ..ConfigChirho::default()
        };

        let mut config_cases_chirho: Vec<(&str, PathBuf, ConfigChirho)> = vec![
            (
                "exact-match",
                platform_root_chirho.clone(),
                platform_config_chirho(&platform_root_chirho),
            ),
            (
                "tenant-adjusted",
                tenant_root_chirho.clone(),
                tenant_config_chirho(&platform_root_chirho, "acme"),
            ),
            (
                "tenant-vs-platform",
                platform_root_chirho.clone(),
                tenant_config_chirho(&platform_root_chirho, "acme"),
            ),
            (
                "whitespace-tenant",
                platform_root_chirho.clone(),
                tenant_config_chirho(&platform_root_chirho, "   "),
            ),
            (
                "mismatch",
                other_root_chirho.clone(),
                platform_config_chirho(&platform_root_chirho),
            ),
        ];
        #[cfg(unix)]
        config_cases_chirho.push((
            "canonicalization-edge",
            symlink_selected_chirho.clone(),
            platform_config_chirho(&symlink_target_chirho),
        ));

        let mut saw_accept_chirho = false;
        let mut saw_reject_chirho = false;
        for (label_chirho, selected_chirho, config_chirho) in &config_cases_chirho {
            let geo_chirho =
                verify_resident_gd7_geo_config_root_binding_chirho(selected_chirho, config_chirho)
                    .is_ok();
            let drill_chirho =
                check_config_root_binding_chirho(selected_chirho, config_chirho).is_ok();
            assert_eq!(
                geo_chirho, drill_chirho,
                "config-root binding verdict diverged on `{label_chirho}`: \
                 geo={geo_chirho} drill={drill_chirho}"
            );
            saw_accept_chirho |= drill_chirho;
            saw_reject_chirho |= !drill_chirho;
        }
        assert!(
            saw_accept_chirho && saw_reject_chirho,
            "the config-root battery must exercise BOTH accept and reject, else parity is vacuous"
        );

        // ---- group binding battery ----
        let group_root_chirho = base_chirho.join("group-root-chirho");
        std::fs::create_dir_all(&group_root_chirho).unwrap();
        let actual_group_chirho = consistency_group_for_root_chirho(&group_root_chirho).unwrap();
        let different_group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
            canonical_root_chirho: "/different-cairn-root-chirho".to_owned(),
        };
        let group_cases_chirho: Vec<(&str, &ConsistencyGroupIdChirho)> = vec![
            ("exact-match", &actual_group_chirho),
            ("mismatch", &different_group_chirho),
        ];
        let mut saw_group_accept_chirho = false;
        let mut saw_group_reject_chirho = false;
        for (label_chirho, group_chirho) in &group_cases_chirho {
            let geo_chirho =
                verify_resident_gd7_geo_group_binding_chirho(&group_root_chirho, group_chirho)
                    .is_ok();
            let drill_chirho = check_group_binding_chirho(&group_root_chirho, group_chirho).is_ok();
            assert_eq!(
                geo_chirho, drill_chirho,
                "group binding verdict diverged on `{label_chirho}`: \
                 geo={geo_chirho} drill={drill_chirho}"
            );
            saw_group_accept_chirho |= drill_chirho;
            saw_group_reject_chirho |= !drill_chirho;
        }
        assert!(
            saw_group_accept_chirho && saw_group_reject_chirho,
            "the group battery must exercise BOTH accept and reject, else parity is vacuous"
        );

        std::fs::remove_dir_all(&base_chirho).unwrap();
    }

    fn held_cluster_config_chirho(local_is_learner_chirho: bool) -> ClusterNodeConfigChirho {
        let extra_held_learner_chirho = if local_is_learner_chirho {
            String::new()
        } else {
            format!(
                r#",{{"raft_id_chirho":4,"pubkey_chirho":"{}","url_chirho":"http://127.0.0.1:3104","learner_chirho":true}}"#,
                "d".repeat(64)
            )
        };
        let bytes_chirho = format!(
            r#"{{
                "group_chirho": {{"kind_chirho":"root","root_path_chirho":"/tmp/cairn-chirho"}},
                "local_raft_id_chirho": 3,
                "members_chirho": [
                    {{"raft_id_chirho":1,"pubkey_chirho":"{}","url_chirho":"http://127.0.0.1:3101","learner_chirho":false}},
                    {{"raft_id_chirho":2,"pubkey_chirho":"{}","url_chirho":"http://127.0.0.1:3102","learner_chirho":false}},
                    {{"raft_id_chirho":3,"pubkey_chirho":"{}","url_chirho":"http://127.0.0.1:3103","learner_chirho":{local_is_learner_chirho}}}{extra_held_learner_chirho}
                ],
                "durable_dir_chirho":"/tmp/cairn-held-raft-chirho",
                "sign_root_chirho":"/tmp/cairn-held-sign-chirho",
                "listen_addr_chirho":"127.0.0.1:3103",
                "tick_ms_chirho":50
            }}"#,
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64)
        )
        .into_bytes();
        parse_cluster_node_file_config_chirho(&bytes_chirho)
            .expect("test cluster config parses")
            .cluster_chirho
    }

    #[test]
    fn held_cluster_requires_learner_without_membership_mutation_chirho() {
        let learner_chirho = held_cluster_config_chirho(true);
        verify_resident_gd7_held_cluster_posture_chirho(&learner_chirho)
            .expect("one local learner is structurally non-electable");

        let voter_chirho = held_cluster_config_chirho(false);
        assert!(
            verify_resident_gd7_held_cluster_posture_chirho(&voter_chirho)
                .unwrap_err()
                .to_string()
                .contains("non-voting learner")
        );

        let mut membership_chirho = held_cluster_config_chirho(true);
        membership_chirho.membership_control_chirho = Some(MembershipControlConfigChirho {
            roster_authority_chirho:
                cairn_writer_elector_http_chirho::membership_control_chirho::RosterAuthorityConfigChirho {
                    roster_path_chirho: PathBuf::from("/tmp/roster-chirho.json"),
                    roster_head_path_chirho: PathBuf::from(
                        "/tmp/roster-head-chirho.json",
                    ),
                    operator_pubkey_hex_chirho: "d".repeat(64),
                    relay_interface_chirho:
                        cairn_roster_config_chirho::RELAY_WIREGUARD_INTERFACE_CHIRHO.to_string(),
                },
            local_node_pubkey_hex_chirho: "c".repeat(64),
            group_id_chirho: membership_chirho.group_chirho.canonical_id_chirho(),
            target_authority_chirho: MembershipTargetAuthorityChirho::RosterWideChirho,
            operator_token_chirho: Some("test-token-chirho".to_owned()),
            fixpoint_step_sleep_chirho: std::time::Duration::from_millis(20),
            fixpoint_max_steps_chirho: 4,
        });
        assert!(
            verify_resident_gd7_held_cluster_posture_chirho(&membership_chirho)
                .unwrap_err()
                .to_string()
                .contains("must not expose membership-control")
        );
    }

    #[test]
    fn served_cluster_requires_exactly_one_local_voter_and_no_learner_role_chirho() {
        let voter_chirho = held_cluster_config_chirho(false);
        verify_resident_gd7_voter_cluster_posture_chirho(&voter_chirho)
            .expect("one local voter is the required served posture");

        let learner_chirho = held_cluster_config_chirho(true);
        assert!(
            verify_resident_gd7_voter_cluster_posture_chirho(&learner_chirho)
                .unwrap_err()
                .to_string()
                .contains("exactly once in the voter roster")
        );

        let mut ambiguous_chirho = held_cluster_config_chirho(false);
        let local_node_chirho = ambiguous_chirho
            .voters_chirho
            .iter()
            .find(|(raft_id_chirho, _node_chirho)| {
                *raft_id_chirho == ambiguous_chirho.local_raft_id_chirho
            })
            .map(|(_raft_id_chirho, node_chirho)| node_chirho.clone())
            .expect("local voter exists");
        ambiguous_chirho
            .learners_chirho
            .push((ambiguous_chirho.local_raft_id_chirho, local_node_chirho));
        assert!(
            verify_resident_gd7_voter_cluster_posture_chirho(&ambiguous_chirho)
                .unwrap_err()
                .to_string()
                .contains("must not also appear in the learner roster")
        );

        let mut missing_held_chirho = held_cluster_config_chirho(false);
        missing_held_chirho.learners_chirho.clear();
        assert!(
            verify_resident_gd7_voter_cluster_posture_chirho(&missing_held_chirho)
                .unwrap_err()
                .to_string()
                .contains("exactly one configured held learner")
        );
    }

    fn require_fault_tolerant_voter_floor_refusal_chirho(
        incompatible_chirho: &ClusterNodeConfigChirho,
        expected_voter_count_chirho: usize,
    ) {
        use crate::a6_authority_composition_chirho::A6GeoAuthorityCompositionRefusalChirho;

        let refusal_chirho =
            validate_resident_gd7_voter_cluster_preflight_chirho(incompatible_chirho)
                .expect_err("a sub-three-voter roster cannot supply a fault-tolerant geo majority");
        assert_eq!(
            refusal_chirho.downcast_ref::<A6GeoAuthorityCompositionRefusalChirho>(),
            Some(
                &A6GeoAuthorityCompositionRefusalChirho::FaultTolerantVoterFloorChirho {
                    voter_count_chirho: expected_voter_count_chirho,
                }
            )
        );
        assert!(refusal_chirho
            .to_string()
            .contains("A6GeoFaultTolerantVoterFloorChirho"));
        assert!(!refusal_chirho
            .to_string()
            .contains("A6GeoMonotonicLeaseRequiredChirho"));
        assert!(!refusal_chirho
            .to_string()
            .contains("exactly once in the voter roster"));
    }

    #[test]
    fn served_cluster_refuses_one_voter_before_authority_state_opens_chirho() {
        let mut one_voter_chirho = held_cluster_config_chirho(false);
        one_voter_chirho
            .voters_chirho
            .retain(|(raft_id_chirho, _node_chirho)| {
                *raft_id_chirho == one_voter_chirho.local_raft_id_chirho
            });
        require_fault_tolerant_voter_floor_refusal_chirho(&one_voter_chirho, 1);
    }

    #[test]
    fn served_cluster_refuses_two_voters_before_authority_state_opens_chirho() {
        let mut two_voters_chirho = held_cluster_config_chirho(false);
        let local_raft_id_chirho = two_voters_chirho.local_raft_id_chirho;
        two_voters_chirho
            .voters_chirho
            .retain(|(raft_id_chirho, _node_chirho)| {
                *raft_id_chirho == 1 || *raft_id_chirho == local_raft_id_chirho
            });
        require_fault_tolerant_voter_floor_refusal_chirho(&two_voters_chirho, 2);
    }

    #[test]
    fn served_cluster_accepts_three_voters_before_authority_state_opens_chirho() {
        let three_voters_chirho = held_cluster_config_chirho(false);
        validate_resident_gd7_voter_cluster_preflight_chirho(&three_voters_chirho)
            .expect("three voters plus one held learner meet the structural code floor");
    }

    #[test]
    fn served_cluster_timing_refuses_before_other_posture_checks_chirho() {
        let mut incompatible_chirho = held_cluster_config_chirho(true);
        incompatible_chirho.tick_interval_chirho = std::time::Duration::from_millis(27);
        let refusal_chirho =
            validate_resident_gd7_voter_cluster_preflight_chirho(&incompatible_chirho)
                .expect_err("relay-incompatible timing must win before the learner-role refusal");
        assert!(
            refusal_chirho
                .to_string()
                .contains("RelayLeaseTransitBudgetIncompatibleChirho"),
            "the first production preflight must retain its named timing identity"
        );
    }
}
