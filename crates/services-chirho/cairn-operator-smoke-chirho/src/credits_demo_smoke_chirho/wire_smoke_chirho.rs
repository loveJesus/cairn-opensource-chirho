// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The LIVE served money arc over the composed configured host: viewer-scope negative + L1 balance,
//! the hostile-body L2 spend (canonical-shaped spoof, #6054), the same-K idempotent replay, the
//! distinct-K definite-no-effect retry, the serve-down operator compensation, the L5 balance, and
//! the packet-provenance-sealed evidence build — every money fact ASSERTED (never inferred) from
//! the verified substrate, the served responses, and the ONE verified cut/census object; every
//! phase snapshot is an ANCESTOR-VERIFIED exact cut of that object's walk (#6050 HOLD B), and a
//! server-thread failure can never be swallowed into a green packet (#6045).
//!
//! Workflow: `spec-chirho/workflows-chirho/reversible-postgres-effect-chirho/credits-demo-localphaseb-smoke-chirho.md`.

use anyhow::{bail, Context, Result};
use cairn_chirho::effect_chirho::postgres_reversible_chirho::{
    CurrentPostgresCompensationPreviewVerdictChirho, EffectTerminalDispositionChirho,
};
use cairn_chirho::{cas_chirho, config_chirho, oauth_chirho};
use cairn_ledger_regenesis_chirho::{
    verified_localphaseb_evidence_from_packet_chirho, EscrowOpKindChirho,
    LocalPhaseBPacketEvidenceChirho, StoragePathChirho, VerifiedLocalPhaseBEvidenceChirho,
};
use cairn_serve_runtime_chirho::{
    execute_current_ledger_host_postgres_compensation_chirho,
    open_shared_ledger_host_postgres_effect_runtime_chirho,
    preview_current_ledger_host_postgres_compensation_chirho,
    serve_with_configured_ledger_host_chirho, ConfiguredLedgerHostRuntimePortsChirho,
    LedgerHostProjectionReadPortChirho, LedgerSubstrateBalancesChirho,
    ServedRequestAbuseLimitsChirho, SharedLedgerHostPostgresEffectRuntimeChirho,
};
use std::sync::Arc;

use super::constants_chirho;
use super::http_smoke_chirho::{
    balance_rows_in_body_chirho, parse_data_attribute_chirho, parse_ssr_balance_chirho,
    principal_occurrences_chirho, ssr_is_fresh_chirho, try_http_get_chirho,
    try_http_request_chirho, unused_local_port_chirho, wait_for_serve_health_chirho,
    HttpSmokeResponseChirho,
};
use super::setup_chirho::{
    pg_comp_receipt_count_chirho, pg_values_row_count_chirho, CreditsDemoSetupChirho,
};
use super::types_chirho::{
    CompensationEvidenceChirho, DistinctRetryEvidenceChirho, ReplayEvidenceChirho,
    SpendEvidenceChirho, ViewerScopeEvidenceChirho,
};

const BALANCE_PATH_CHIRHO: &str = "/ssr-chirho/credits-demo-chirho";
const SPEND_PATH_CHIRHO: &str = "/app-chirho/credits-demo-chirho/spend-chirho";

/// A CANONICAL-SHAPED spoof principal (#6054/#6055): a valid `user/<16 lowerhex>` coordinate, so a
/// body-authority regression cannot hide behind shape validation — it must actually prefer the
/// session principal or the smoke fails on the exact-coordinate absent/uncharged assertion.
const ATTACKER_PRINCIPAL_CHIRHO: &str = "user/aaaaaaaaaaaaaaaa";
/// A deliberately MALFORMED spoof for the separate parser-rejection probe (the old grain — kept as
/// a second boundary check, never the load-bearing authority probe).
const MALFORMED_ATTACKER_PRINCIPAL_CHIRHO: &str = "user/attacker";

/// The served-arc evidence the orchestrator folds into the packet (leg 1 + leg 4), including the
/// packet-provenance-sealed verified evidence object both the wire and the packet consume.
pub struct WireOutcomeChirho {
    pub server_chirho: String,
    pub anonymous_refusal_chirho: ViewerScopeEvidenceChirho,
    pub l1_chirho: ViewerScopeEvidenceChirho,
    pub l2_chirho: SpendEvidenceChirho,
    pub replay_chirho: ReplayEvidenceChirho,
    pub r4b_chirho: DistinctRetryEvidenceChirho,
    pub compensation_chirho: CompensationEvidenceChirho,
    pub l5_chirho: ViewerScopeEvidenceChirho,
    pub served_viewer_principal_chirho: String,
    pub minted_chirho: u64,
    pub balance_l1_chirho: u64,
    pub balance_after_l2_chirho: u64,
    pub balance_final_chirho: u64,
    pub settlement_after_l2_chirho: u64,
    pub settlement_final_chirho: u64,
    pub payer_net_final_chirho: u64,
    pub settlement_net_final_chirho: u64,
    pub held_sum_final_chirho: u64,
    pub final_net_supply_chirho: u64,
    /// The ephemeral bearer tokens the arc used — needles for the packet no-leak scan (#6067).
    pub session_tokens_chirho: Vec<String>,
    pub packet_evidence_chirho: LocalPhaseBPacketEvidenceChirho,
    pub census_saga_count_chirho: usize,
    pub census_settlement_meter_sum_chirho: u64,
    pub census_structure_bound_chirho: bool,
    pub l1_matches_verified_regenesis_net_chirho: bool,
    pub l5_matches_verified_final_net_chirho: bool,
}

/// Adjudicate a phase result together with its server's whole-life result (#6047/#6062): phase
/// error precedence, server failure alone still fails, and a double failure carries BOTH causes.
fn join_phase_and_server_chirho<T>(
    phase_chirho: Result<T>,
    server_chirho: Result<()>,
) -> Result<T> {
    match (phase_chirho, server_chirho) {
        (Ok(value_chirho), Ok(())) => Ok(value_chirho),
        (Ok(_), Err(server_error_chirho)) => Err(server_error_chirho),
        (Err(phase_error_chirho), Ok(())) => Err(phase_error_chirho),
        (Err(phase_error_chirho), Err(server_error_chirho)) => Err(phase_error_chirho.context(
            format!("server thread also failed: {server_error_chirho:?}"),
        )),
    }
}

/// One phase snapshot's EXACT cut coordinates (#6050 HOLD B): seq + tail-line digest + genesis,
/// later ancestor-verified against the ONE evidence walk — a same-seq forked state refuses.
struct SnapshotCutChirho {
    label_chirho: &'static str,
    seq_chirho: u64,
    tail_line_digest_chirho: String,
    genesis_digest_chirho: String,
}

fn snapshot_cut_chirho(
    label_chirho: &'static str,
    balances_chirho: &LedgerSubstrateBalancesChirho,
) -> SnapshotCutChirho {
    SnapshotCutChirho {
        label_chirho,
        seq_chirho: balances_chirho.tail_seq_chirho,
        tail_line_digest_chirho: balances_chirho.tail_line_digest_chirho.clone(),
        genesis_digest_chirho: balances_chirho.genesis_digest_chirho.clone(),
    }
}

fn account_net_chirho(
    balances_chirho: &LedgerSubstrateBalancesChirho,
    owner_chirho: &str,
    kind_chirho: &str,
) -> u64 {
    *balances_chirho
        .account_nets_chirho
        .get(&(owner_chirho.to_string(), kind_chirho.to_string()))
        .unwrap_or(&0)
}

fn account_held_chirho(
    balances_chirho: &LedgerSubstrateBalancesChirho,
    owner_chirho: &str,
    kind_chirho: &str,
) -> u64 {
    *balances_chirho
        .account_held_chirho
        .get(&(owner_chirho.to_string(), kind_chirho.to_string()))
        .unwrap_or(&0)
}

fn viewer_scope_evidence_chirho(
    method_chirho: &str,
    response_chirho: &HttpSmokeResponseChirho,
    payer_chirho: &str,
    settlement_owner_chirho: &str,
) -> ViewerScopeEvidenceChirho {
    let body_text_chirho = response_chirho.body_text_chirho();
    ViewerScopeEvidenceChirho {
        method_chirho: method_chirho.to_string(),
        path_chirho: BALANCE_PATH_CHIRHO.to_string(),
        status_chirho: response_chirho.status_chirho,
        body_chirho: cas_chirho::hash_chirho(&response_chirho.body_chirho),
        parsed_balance_chirho: parse_ssr_balance_chirho(&body_text_chirho),
        fresh_chirho: ssr_is_fresh_chirho(&body_text_chirho),
        viewer_rows_chirho: balance_rows_in_body_chirho(&body_text_chirho),
        settlement_rows_in_body_chirho: principal_occurrences_chirho(
            &body_text_chirho,
            settlement_owner_chirho,
        ),
        viewer_principal_occurrences_chirho: principal_occurrences_chirho(
            &body_text_chirho,
            payer_chirho,
        ),
        missing_viewer_refusal_chirho: body_text_chirho
            .contains("missing-viewer-context-refusal-chirho"),
        served_descriptor_chirho: parse_data_attribute_chirho(
            &body_text_chirho,
            "projection-descriptor-chirho",
        ),
        served_family_chirho: parse_data_attribute_chirho(
            &body_text_chirho,
            "projection-family-chirho",
        ),
        served_seq_chirho: parse_data_attribute_chirho(&body_text_chirho, "projection-seq-chirho")
            .and_then(|value_chirho| value_chirho.parse().ok()),
        served_hlc_physical_ms_chirho: parse_data_attribute_chirho(
            &body_text_chirho,
            "projection-hlc-physical-chirho",
        )
        .and_then(|value_chirho| value_chirho.parse().ok()),
        served_hlc_logical_chirho: parse_data_attribute_chirho(
            &body_text_chirho,
            "projection-hlc-logical-chirho",
        )
        .and_then(|value_chirho| value_chirho.parse().ok()),
        served_prefix_digest_chirho: parse_data_attribute_chirho(
            &body_text_chirho,
            "projection-prefix-chirho",
        ),
        served_state_digest_chirho: parse_data_attribute_chirho(
            &body_text_chirho,
            "projection-state-chirho",
        ),
    }
}

/// One NAMED verified cut's expected coordinates (typed — no long positional list, no allow).
struct ExpectedServedCutChirho<'cut_chirho> {
    descriptor_chirho: &'cut_chirho str,
    family_chirho: &'cut_chirho str,
    seq_chirho: u64,
    hlc_physical_ms_chirho: u64,
    hlc_logical_chirho: u32,
    prefix_digest_chirho: &'cut_chirho str,
    view_digest_chirho: &'cut_chirho str,
}

/// Require the SERVED page's authenticated cut coordinates to EQUAL a named verified cut
/// (#6071): same descriptor revision, source family, seq, HLC, signed prefix, and state/view
/// digest — a Fresh response from any other cut with the same balance value refuses.
fn assert_served_cut_matches_chirho(
    label_chirho: &str,
    evidence_chirho: &ViewerScopeEvidenceChirho,
    expected_cut_chirho: &ExpectedServedCutChirho<'_>,
) -> Result<()> {
    let served_chirho = (
        evidence_chirho.served_descriptor_chirho.as_deref(),
        evidence_chirho.served_family_chirho.as_deref(),
        evidence_chirho.served_seq_chirho,
        evidence_chirho.served_hlc_physical_ms_chirho,
        evidence_chirho.served_hlc_logical_chirho,
        evidence_chirho.served_prefix_digest_chirho.as_deref(),
        evidence_chirho.served_state_digest_chirho.as_deref(),
    );
    let expected_chirho = (
        Some(expected_cut_chirho.descriptor_chirho),
        Some(expected_cut_chirho.family_chirho),
        Some(expected_cut_chirho.seq_chirho),
        Some(expected_cut_chirho.hlc_physical_ms_chirho),
        Some(expected_cut_chirho.hlc_logical_chirho),
        Some(expected_cut_chirho.prefix_digest_chirho),
        Some(expected_cut_chirho.view_digest_chirho),
    );
    if served_chirho != expected_chirho {
        bail!(
            "{label_chirho} served cut coordinates {served_chirho:?} do not equal the named \
             verified cut {expected_chirho:?}"
        );
    }
    Ok(())
}

fn open_host_chirho(
    setup_chirho: &CreditsDemoSetupChirho,
) -> Result<Arc<LedgerHostProjectionReadPortChirho>> {
    let config_chirho = config_chirho::load_digest_bound_config_chirho(
        &setup_chirho.config_path_chirho,
        &setup_chirho.expected_config_digest_chirho,
    )?;
    let ledger_host_chirho = config_chirho
        .ledger_host_chirho
        .ok_or_else(|| anyhow::anyhow!("config lost its ledger_host block"))?;
    Ok(Arc::new(
        LedgerHostProjectionReadPortChirho::open_existing_chirho(
            &setup_chirho.root_chirho,
            &setup_chirho.config_path_chirho,
            &ledger_host_chirho,
        )?,
    ))
}

fn open_pg_runtime_chirho(
    setup_chirho: &CreditsDemoSetupChirho,
    host_chirho: Arc<LedgerHostProjectionReadPortChirho>,
) -> Result<SharedLedgerHostPostgresEffectRuntimeChirho> {
    let config_chirho = config_chirho::load_digest_bound_config_chirho(
        &setup_chirho.config_path_chirho,
        &setup_chirho.expected_config_digest_chirho,
    )?;
    let ledger_config_chirho = config_chirho
        .ledger_host_chirho
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("config lost its ledger_host block"))?;
    if ledger_config_chirho.postgres_effect_chirho.is_none() {
        anyhow::bail!("config lost its postgres_effect block");
    }
    open_shared_ledger_host_postgres_effect_runtime_chirho(
        &setup_chirho.root_chirho,
        &setup_chirho.config_path_chirho,
        host_chirho,
        ledger_config_chirho,
    )
}

/// A configured host served on a DEDICATED OS thread (its own tokio runtime). All HTTP and the sync
/// `postgres` driver run on the caller's thread OUTSIDE any tokio runtime — the sync `postgres`
/// crate spins its own current-thread runtime internally, so calling it from within `block_on` would
/// recreate the nested-runtime panic this smoke exists to disprove. The thread returns `Result` and
/// EVERY failure mode surfaces (#6045/#6047): a Runtime build error, a serve error, a premature
/// serve exit (even `Ok`), and a join panic all fail the smoke — never a swallowed false-green.
struct ServerHandleChirho {
    shutdown_chirho: std::sync::mpsc::Sender<()>,
    thread_chirho: Option<std::thread::JoinHandle<Result<()>>>,
}

impl ServerHandleChirho {
    /// Signal shutdown and adjudicate the server thread's whole life. The signal send result is
    /// deliberately ignored — if the thread already exited, the JOIN result carries the cause.
    fn shutdown_chirho(mut self) -> Result<()> {
        let _ = self.shutdown_chirho.send(());
        let thread_chirho = self
            .thread_chirho
            .take()
            .ok_or_else(|| anyhow::anyhow!("server thread handle already taken"))?;
        match thread_chirho.join() {
            Ok(result_chirho) => result_chirho,
            Err(panic_chirho) => bail!("server thread panicked: {panic_chirho:?}"),
        }
    }
}

fn spawn_server_chirho(
    root_chirho: std::path::PathBuf,
    port_chirho: u16,
    host_chirho: Arc<LedgerHostProjectionReadPortChirho>,
    pg_chirho: SharedLedgerHostPostgresEffectRuntimeChirho,
) -> Result<ServerHandleChirho> {
    let (shutdown_tx_chirho, shutdown_rx_chirho) = std::sync::mpsc::channel::<()>();
    // Startup handshake (#6059): runtime-construction failure reaches the caller DIRECTLY —
    // never degraded into a later health-wait timeout that a phase error would mask.
    let (startup_tx_chirho, startup_rx_chirho) = std::sync::mpsc::channel::<Result<()>>();
    let thread_chirho = std::thread::spawn(move || -> Result<()> {
        let runtime_chirho = match tokio::runtime::Runtime::new() {
            Ok(runtime_chirho) => {
                let _ = startup_tx_chirho.send(Ok(()));
                runtime_chirho
            }
            Err(error_chirho) => {
                let _ = startup_tx_chirho.send(Err(anyhow::anyhow!(
                    "build the server tokio runtime: {error_chirho}"
                )));
                bail!("build the server tokio runtime: {error_chirho}");
            }
        };
        runtime_chirho.block_on(async move {
            // select! cancels the (non-'static, root-borrowing) serve future when shutdown fires,
            // instead of tokio::spawn (which would require a 'static future). In this harness the
            // server may exit ONLY via the shutdown signal — a serve-arm win is an error even on
            // Ok (#6047 premature-exit rule) — and `biased` makes a ready serve FAILURE win over a
            // simultaneously-ready shutdown (#6059: no green-cancelled ready error).
            tokio::select! {
                biased;
                serve_chirho = serve_with_configured_ledger_host_chirho(
                    &root_chirho,
                    port_chirho,
                    8,
                    cairn_serve_runtime_chirho::ServeAuthTokensChirho::default(),
                    false,
                    ServedRequestAbuseLimitsChirho::default(),
                    ConfiguredLedgerHostRuntimePortsChirho::composed_chirho(host_chirho, Some(pg_chirho)),
                ) => match serve_chirho {
                    Ok(()) => bail!("server exited prematurely (serve returned before shutdown)"),
                    Err(error_chirho) => {
                        Err(anyhow::anyhow!("server serve loop failed: {error_chirho:?}"))
                    }
                },
                shutdown_chirho = tokio::task::spawn_blocking(move || shutdown_rx_chirho.recv()) => {
                    match shutdown_chirho {
                        Ok(Ok(())) => Ok(()),
                        Ok(Err(recv_error_chirho)) => Err(anyhow::anyhow!(
                            "shutdown channel closed without a signal: {recv_error_chirho}"
                        )),
                        Err(join_error_chirho) => Err(anyhow::anyhow!(
                            "shutdown wait task failed: {join_error_chirho}"
                        )),
                    }
                }
            }
        })
    });
    match startup_rx_chirho.recv() {
        Ok(Ok(())) => Ok(ServerHandleChirho {
            shutdown_chirho: shutdown_tx_chirho,
            thread_chirho: Some(thread_chirho),
        }),
        Ok(Err(error_chirho)) => {
            let _ = thread_chirho.join();
            Err(error_chirho)
        }
        Err(_recv_error_chirho) => match thread_chirho.join() {
            Ok(Ok(())) => bail!("server thread exited before its startup signal"),
            Ok(Err(error_chirho)) => Err(error_chirho),
            Err(panic_chirho) => bail!("server thread panicked during startup: {panic_chirho:?}"),
        },
    }
}

pub fn run_credits_demo_wire_chirho(
    setup_chirho: &CreditsDemoSetupChirho,
) -> Result<WireOutcomeChirho> {
    let payer_chirho = setup_chirho.payer_chirho.clone();
    let settlement_chirho = setup_chirho.settlement_owner_chirho.clone();
    let kind_chirho = setup_chirho.billing_kind_chirho.clone();
    if ATTACKER_PRINCIPAL_CHIRHO == payer_chirho {
        bail!("spoof principal collided with the verified payer (astronomically unlikely)");
    }

    // --- PHASE 1: serve up (dedicated thread), viewer-scope + L1 + L2 + replay + R4b ---
    let host1_chirho = open_host_chirho(setup_chirho)?;
    let pg1_chirho = open_pg_runtime_chirho(setup_chirho, host1_chirho.clone())?;
    let port_chirho = unused_local_port_chirho()?;
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let server_chirho = format!("http://{addr_chirho}");
    let server1_chirho = spawn_server_chirho(
        setup_chirho.root_chirho.clone(),
        port_chirho,
        host1_chirho.clone(),
        pg1_chirho.clone(),
    )?;
    let phase1_chirho = drive_phase1_chirho(
        &addr_chirho,
        &host1_chirho,
        setup_chirho,
        &payer_chirho,
        &settlement_chirho,
        &kind_chirho,
    );
    // Shutdown FIRST even on a phase error (#6047 ordering), capture BOTH results, and ATTACH-BOTH
    // (#6062): the phase error keeps precedence but must CARRY a simultaneous server failure as
    // context — neither cause is ever discarded; a server failure alone still fails.
    let shutdown1_chirho = server1_chirho.shutdown_chirho();
    drop(pg1_chirho);
    drop(host1_chirho);
    let phase1_chirho = join_phase_and_server_chirho(phase1_chirho, shutdown1_chirho)?;

    // --- PHASE 2: serve down, operator compensation (sync, off any tokio runtime) ---
    let host2_chirho = open_host_chirho(setup_chirho)?;
    let pg2_chirho = open_pg_runtime_chirho(setup_chirho, host2_chirho.clone())?;
    let compensation_result_chirho = drive_compensation_chirho(
        &pg2_chirho,
        &host2_chirho,
        setup_chirho,
        &payer_chirho,
        &settlement_chirho,
        &kind_chirho,
    )?;
    let compensation_chirho = compensation_result_chirho.evidence_chirho;
    let balances_after_comp_chirho = host2_chirho.read_substrate_balances_chirho()?;
    drop(pg2_chirho);
    drop(host2_chirho);

    // --- PHASE 3: serve up again (dedicated thread), L5 ---
    let host3_chirho = open_host_chirho(setup_chirho)?;
    let pg3_chirho = open_pg_runtime_chirho(setup_chirho, host3_chirho.clone())?;
    let port3_chirho = unused_local_port_chirho()?;
    let addr3_chirho = format!("127.0.0.1:{port3_chirho}");
    let server3_chirho = spawn_server_chirho(
        setup_chirho.root_chirho.clone(),
        port3_chirho,
        host3_chirho.clone(),
        pg3_chirho.clone(),
    )?;
    let l5_result_chirho = drive_l5_chirho(
        &addr3_chirho,
        setup_chirho,
        &payer_chirho,
        &settlement_chirho,
    );
    let shutdown3_chirho = server3_chirho.shutdown_chirho();
    drop(pg3_chirho);
    drop(host3_chirho);
    let (l5_chirho, l5_token_chirho) =
        join_phase_and_server_chirho(l5_result_chirho, shutdown3_chirho)?;

    // --- THE ONE VERIFIED EVIDENCE OBJECT (packet-provenance-sealed): built through the host's
    // lent verified ports + the regenesis parent from the immutable H3 packet bytes. ---
    let host4_chirho = open_host_chirho(setup_chirho)?;
    let packet_bytes_chirho = std::fs::read(&setup_chirho.h3_packet_path_chirho)
        .context("re-read immutable H3 evidence packet for the wire evidence build")?;
    let retained_head_chirho =
        StoragePathChirho(setup_chirho.retained_regenesis_head_path_chirho.clone());
    let packet_evidence_chirho = host4_chirho.with_localphaseb_evidence_ports_chirho(
        &setup_chirho.balance_projection_name_chirho,
        |ports_chirho| {
            verified_localphaseb_evidence_from_packet_chirho(
                &packet_bytes_chirho,
                &setup_chirho.regenesis_packet_digest_chirho,
                &setup_chirho.balance_projection_name_chirho,
                ports_chirho,
                &retained_head_chirho,
            )
        },
    )?;
    let evidence_chirho = packet_evidence_chirho.evidence_chirho();

    // Census structural pin: the EXACT per-record escrow interval (#11).
    let (census_saga_count_chirho, census_settlement_meter_sum_chirho) =
        assert_census_structure_chirho(setup_chirho, evidence_chirho)?;

    // HOLD B (iii): EVERY phase snapshot is an ancestor-verified exact cut of the ONE walk.
    let final_snapshot_chirho =
        snapshot_cut_chirho("after-compensation", &balances_after_comp_chirho);
    let mut snapshots_chirho = phase1_chirho.snapshots_chirho;
    snapshots_chirho.push(compensation_result_chirho.before_snapshot_chirho);
    snapshots_chirho.push(final_snapshot_chirho);
    for snapshot_chirho in &snapshots_chirho {
        if snapshot_chirho.genesis_digest_chirho != evidence_chirho.genesis_digest_chirho().0 {
            bail!(
                "phase snapshot '{}' binds a different journal instance",
                snapshot_chirho.label_chirho
            );
        }
        let ancestor_chirho =
            evidence_chirho.ancestor_line_digest_at_seq_chirho(snapshot_chirho.seq_chirho)?;
        if ancestor_chirho.0 != snapshot_chirho.tail_line_digest_chirho {
            bail!(
                "phase snapshot '{}' is not an ancestor-verified cut of the verified chain \
                 (same-seq fork or splice)",
                snapshot_chirho.label_chirho
            );
        }
    }
    // The L1 snapshot must BE the regenesis cut, and the final snapshot must BE the walk tail.
    if phase1_chirho.l1_seq_chirho != evidence_chirho.regenesis_source_seq_chirho() {
        bail!("L1 snapshot seq is not the verified regenesis cut seq");
    }
    if balances_after_comp_chirho.tail_seq_chirho != evidence_chirho.tail_seq_chirho()
        || balances_after_comp_chirho.tail_line_digest_chirho
            != evidence_chirho.tail_line_digest_chirho().0
    {
        bail!("final balances cut does not equal the verified walk tail");
    }

    // Fresh-never-lies viewer binding: served route balances == VERIFIED cut nets.
    let l1_matches_verified_regenesis_net_chirho = phase1_chirho.l1_chirho.parsed_balance_chirho
        == Some(evidence_chirho.regenesis_account_net_chirho());
    let l5_matches_verified_final_net_chirho =
        l5_chirho.parsed_balance_chirho == Some(evidence_chirho.final_account_net_chirho());
    if !l1_matches_verified_regenesis_net_chirho || !l5_matches_verified_final_net_chirho {
        bail!("served L1/L5 balances do not equal the verified cut nets (viewer binding broken)");
    }
    // #6071 served-view exact-cut: L1/L5 assert on their NAMED verified cuts, never value-only.
    let family_chirho = packet_evidence_chirho.source_family_id_chirho().to_string();
    assert_served_cut_matches_chirho(
        "L1",
        &phase1_chirho.l1_chirho,
        &ExpectedServedCutChirho {
            descriptor_chirho: &evidence_chirho.descriptor_digest_chirho().0,
            family_chirho: &family_chirho,
            seq_chirho: evidence_chirho.regenesis_source_seq_chirho(),
            hlc_physical_ms_chirho: evidence_chirho
                .regenesis_source_hlc_chirho()
                .physical_ms_chirho,
            hlc_logical_chirho: evidence_chirho.regenesis_source_hlc_chirho().logical_chirho,
            prefix_digest_chirho: &evidence_chirho.regenesis_signed_prefix_digest_chirho().0,
            view_digest_chirho: evidence_chirho.regenesis_view_digest_hex_chirho(),
        },
    )?;
    assert_served_cut_matches_chirho(
        "L5",
        &l5_chirho,
        &ExpectedServedCutChirho {
            descriptor_chirho: &evidence_chirho.descriptor_digest_chirho().0,
            family_chirho: &family_chirho,
            seq_chirho: evidence_chirho.final_source_seq_chirho(),
            hlc_physical_ms_chirho: evidence_chirho.final_source_hlc_chirho().physical_ms_chirho,
            hlc_logical_chirho: evidence_chirho.final_source_hlc_chirho().logical_chirho,
            prefix_digest_chirho: &evidence_chirho.tail_line_digest_chirho().0,
            view_digest_chirho: evidence_chirho.final_view_digest_hex_chirho(),
        },
    )?;
    // #6073 three-source initial-minted cross-equality: the census Mint-record amount, the
    // digest-bound plan amount, and the sealed regenesis-cut net must all agree.
    let census_mint_amount_chirho = evidence_chirho.op_census_chirho().mint_total_amount_chirho;
    if evidence_chirho.regenesis_account_net_chirho() != setup_chirho.plan_mint_amount_chirho
        || census_mint_amount_chirho != setup_chirho.plan_mint_amount_chirho
    {
        bail!(
            "initial-minted sources disagree: census mint {census_mint_amount_chirho}, plan {},              regenesis cut net {}",
            setup_chirho.plan_mint_amount_chirho,
            evidence_chirho.regenesis_account_net_chirho()
        );
    }

    // Final conservation reads (authoritative fresh reread).
    let payer_net_final_chirho =
        account_net_chirho(&balances_after_comp_chirho, &payer_chirho, &kind_chirho);
    let settlement_net_final_chirho = account_net_chirho(
        &balances_after_comp_chirho,
        &settlement_chirho,
        &kind_chirho,
    );
    let held_sum_final_chirho: u64 = balances_after_comp_chirho
        .account_held_chirho
        .values()
        .try_fold(0u64, |sum_chirho, held_chirho| {
            sum_chirho.checked_add(*held_chirho)
        })
        .ok_or_else(|| anyhow::anyhow!("held sum overflow"))?;
    if held_sum_final_chirho != 0 {
        bail!("final substrate held sum was {held_sum_final_chirho}, expected 0");
    }
    // #6072: the journal's OWN supply coordinate, exact-selected by billing kind — a missing
    // entry REFUSES, and it must equal the verified initial mint (net supply is never "minted").
    let final_net_supply_chirho = *balances_after_comp_chirho
        .net_supply_by_kind_chirho
        .get(&kind_chirho)
        .ok_or_else(|| anyhow::anyhow!("billing kind absent from the verified net-supply fold"))?;
    if final_net_supply_chirho != setup_chirho.plan_mint_amount_chirho {
        bail!(
            "final net supply {final_net_supply_chirho} does not equal the verified initial mint              {}",
            setup_chirho.plan_mint_amount_chirho
        );
    }
    if payer_net_final_chirho != evidence_chirho.final_account_net_chirho() {
        bail!("final substrate payer net does not equal the verified final cut net");
    }
    if census_settlement_meter_sum_chirho != settlement_net_final_chirho {
        bail!(
            "settlement CREDIT meter sum {census_settlement_meter_sum_chirho} does not equal the \
             final settlement net {settlement_net_final_chirho}"
        );
    }
    if evidence_chirho.regenesis_view_digest_hex_chirho()
        == evidence_chirho.final_view_digest_hex_chirho()
    {
        bail!("regenesis and final verified view digests were identical (expected distinct views)");
    }

    Ok(WireOutcomeChirho {
        server_chirho,
        anonymous_refusal_chirho: phase1_chirho.anonymous_refusal_chirho,
        l1_chirho: phase1_chirho.l1_chirho,
        l2_chirho: phase1_chirho.l2_chirho,
        replay_chirho: phase1_chirho.replay_chirho,
        r4b_chirho: phase1_chirho.r4b_chirho,
        compensation_chirho,
        l5_chirho,
        served_viewer_principal_chirho: phase1_chirho.served_viewer_principal_chirho,
        session_tokens_chirho: vec![
            phase1_chirho.session_token_chirho,
            phase1_chirho.probe_session_token_chirho,
            l5_token_chirho,
        ],
        minted_chirho: setup_chirho.plan_mint_amount_chirho,
        balance_l1_chirho: phase1_chirho.balance_l1_chirho,
        balance_after_l2_chirho: phase1_chirho.balance_after_l2_chirho,
        balance_final_chirho: payer_net_final_chirho,
        settlement_after_l2_chirho: phase1_chirho.settlement_after_l2_chirho,
        settlement_final_chirho: settlement_net_final_chirho,
        payer_net_final_chirho,
        settlement_net_final_chirho,
        held_sum_final_chirho,
        final_net_supply_chirho,
        packet_evidence_chirho,
        census_saga_count_chirho,
        census_settlement_meter_sum_chirho,
        census_structure_bound_chirho: true,
        l1_matches_verified_regenesis_net_chirho,
        l5_matches_verified_final_net_chirho,
    })
}

/// Pin the EXACT whole-arc escrow interval from the verified census (#11): one mint; exactly six
/// escrow records in three consecutive one-saga pairs — Hold→Finalize with the settlement CREDIT
/// (L2), Hold→Release with NO credit (R4b), Hold→Finalize with the credit (L4 compensation) — all
/// on the payer's billing account at exactly the signed price, sagas pairwise DISTINCT, holds
/// carrying no credit, and the interval running from the regenesis cut + 1 to exactly the final
/// cut. Equal aggregate totals with wrong ordering/control/amount REFUSE here.
fn assert_census_structure_chirho(
    setup_chirho: &CreditsDemoSetupChirho,
    evidence_chirho: &VerifiedLocalPhaseBEvidenceChirho,
) -> Result<(usize, u64)> {
    let price_chirho = u64::try_from(constants_chirho::POSTGRES_REVERSIBLE_PRICE_CHIRHO)
        .context("signed price is non-negative")?;
    let census_chirho = evidence_chirho.op_census_chirho();
    if census_chirho.mint_count_chirho != 1 {
        bail!(
            "census mint count {} != 1 (exactly the genesis mint)",
            census_chirho.mint_count_chirho
        );
    }
    let records_chirho = &census_chirho.escrow_records_chirho;
    if records_chirho.len() != 6 {
        bail!(
            "census escrow record count {} != 6 (three saga pairs)",
            records_chirho.len()
        );
    }
    let cut_seq_chirho = evidence_chirho.regenesis_source_seq_chirho();
    for (index_chirho, record_chirho) in records_chirho.iter().enumerate() {
        let index_seq_chirho = u64::try_from(index_chirho)
            .map_err(|_error_chirho| anyhow::anyhow!("escrow index overflow"))?;
        let expected_seq_chirho = cut_seq_chirho
            .checked_add(1)
            .and_then(|seq_chirho| seq_chirho.checked_add(index_seq_chirho))
            .ok_or_else(|| anyhow::anyhow!("cut seq overflow"))?;
        if record_chirho.seq_chirho != expected_seq_chirho {
            bail!("escrow records are not the consecutive post-cut interval");
        }
        if record_chirho.escrow_account_owner_chirho != setup_chirho.payer_chirho
            || record_chirho.escrow_account_kind_chirho != setup_chirho.billing_kind_chirho
        {
            bail!(
                "escrow record at seq {} is not on the payer billing account",
                record_chirho.seq_chirho
            );
        }
        if record_chirho.escrow_amount_chirho != price_chirho {
            bail!(
                "escrow record at seq {} amount {} != the signed price {price_chirho}",
                record_chirho.seq_chirho,
                record_chirho.escrow_amount_chirho
            );
        }
    }
    let pair_shapes_chirho = [
        ("L2 spend", EscrowOpKindChirho::FinalizeChirho, true),
        ("R4b retry", EscrowOpKindChirho::ReleaseChirho, false),
        ("L4 compensation", EscrowOpKindChirho::FinalizeChirho, true),
    ];
    let mut sagas_chirho = Vec::with_capacity(3);
    let mut meter_sum_chirho: u64 = 0;
    for (pair_index_chirho, (label_chirho, second_op_chirho, credited_chirho)) in
        pair_shapes_chirho.iter().enumerate()
    {
        let first_chirho = &records_chirho[pair_index_chirho * 2];
        let second_chirho = &records_chirho[pair_index_chirho * 2 + 1];
        if first_chirho.op_kind_chirho != EscrowOpKindChirho::HoldChirho
            || second_chirho.op_kind_chirho != *second_op_chirho
        {
            bail!("{label_chirho} pair does not have the exact Hold→{second_op_chirho:?} shape");
        }
        if first_chirho.control_saga_chirho != second_chirho.control_saga_chirho {
            bail!("{label_chirho} pair records are not one control saga");
        }
        if first_chirho.control_step_chirho != second_chirho.control_step_chirho {
            bail!("{label_chirho} pair records are not one control step (#6059)");
        }
        if first_chirho.settlement_credit_leg_chirho.is_some() {
            bail!("{label_chirho} Hold carries a settlement credit leg");
        }
        match (credited_chirho, &second_chirho.settlement_credit_leg_chirho) {
            (true, Some((owner_chirho, kind_chirho, amount_chirho)))
                if owner_chirho == &setup_chirho.settlement_owner_chirho
                    && kind_chirho == &setup_chirho.billing_kind_chirho
                    && *amount_chirho == price_chirho =>
            {
                meter_sum_chirho = meter_sum_chirho
                    .checked_add(*amount_chirho)
                    .ok_or_else(|| anyhow::anyhow!("settlement meter overflow"))?;
            }
            (true, _) => bail!(
                "{label_chirho} Finalize settlement credit leg is not exactly \
                 settlement/kind/price"
            ),
            (false, None) => {}
            (false, Some(_)) => bail!("{label_chirho} Release carries a settlement credit leg"),
        }
        sagas_chirho.push(first_chirho.control_saga_chirho.clone());
    }
    if sagas_chirho[0] == sagas_chirho[1]
        || sagas_chirho[1] == sagas_chirho[2]
        || sagas_chirho[0] == sagas_chirho[2]
    {
        bail!("control sagas are not pairwise distinct across the three pairs");
    }
    let expected_final_seq_chirho = cut_seq_chirho
        .checked_add(6)
        .ok_or_else(|| anyhow::anyhow!("cut seq overflow"))?;
    if evidence_chirho.final_source_seq_chirho() != expected_final_seq_chirho {
        bail!("final cut is not exactly the six-record interval end");
    }
    Ok((sagas_chirho.len(), meter_sum_chirho))
}

struct Phase1OutcomeChirho {
    anonymous_refusal_chirho: ViewerScopeEvidenceChirho,
    l1_chirho: ViewerScopeEvidenceChirho,
    l1_seq_chirho: u64,
    l2_chirho: SpendEvidenceChirho,
    replay_chirho: ReplayEvidenceChirho,
    r4b_chirho: DistinctRetryEvidenceChirho,
    balance_l1_chirho: u64,
    balance_after_l2_chirho: u64,
    settlement_after_l2_chirho: u64,
    served_viewer_principal_chirho: String,
    session_token_chirho: String,
    probe_session_token_chirho: String,
    snapshots_chirho: Vec<SnapshotCutChirho>,
}

fn drive_phase1_chirho(
    addr_chirho: &str,
    host_chirho: &LedgerHostProjectionReadPortChirho,
    setup_chirho: &CreditsDemoSetupChirho,
    payer_chirho: &str,
    settlement_chirho: &str,
    kind_chirho: &str,
) -> Result<Phase1OutcomeChirho> {
    wait_for_serve_health_chirho(addr_chirho)?;
    // App bearer tokens are SCOPED tokens by law — issue one through the real oauth flow (signed
    // client + payer credential). The AUTHENTICATED served viewer coordinate is the principal the
    // SIGNED scoped-token record binds (never a copy of setup.payer).
    let issue_chirho = oauth_chirho::issue_scoped_token_chirho(
        &setup_chirho.root_chirho,
        payer_chirho,
        &setup_chirho.payer_credential_chirho,
        &setup_chirho.oauth_client_id_chirho,
        vec!["invoke_chirho".to_string()],
    )?;
    let bearer_chirho = format!("Bearer {}", issue_chirho.token_chirho);
    let served_viewer_principal_chirho = issue_chirho.record_chirho.principal_chirho.clone();
    let mut snapshots_chirho = Vec::new();

    // Viewer-scope negative: anonymous GET refuses and leaks zero balance rows.
    let anon_chirho = try_http_get_chirho(addr_chirho, BALANCE_PATH_CHIRHO)?;
    let anonymous_refusal_chirho =
        viewer_scope_evidence_chirho("GET", &anon_chirho, payer_chirho, settlement_chirho);
    // #6082-E/#6084: the anonymous negative pins the TYPED missing-viewer refusal — exact 400
    // plus the bounded discriminator from the projection-read seam — never any generic non-200.
    if anonymous_refusal_chirho.status_chirho != 400
        || !anonymous_refusal_chirho.missing_viewer_refusal_chirho
    {
        let body_excerpt_chirho: String =
            anon_chirho.body_text_chirho().chars().take(300).collect();
        bail!(
            "anonymous balance GET was not the typed missing-viewer refusal: status={}              body[..300]={body_excerpt_chirho}",
            anonymous_refusal_chirho.status_chirho
        );
    }
    if anonymous_refusal_chirho.viewer_rows_chirho != 0
        || anonymous_refusal_chirho.viewer_principal_occurrences_chirho != 0
    {
        bail!("anonymous balance GET leaked balance rows or the payer principal");
    }

    // Parser-rejection probe (the SECOND spoof boundary, #6055 optional grain): a malformed
    // principal + malformed token must refuse without serving or effects — this exercises input
    // validation; the load-bearing authority probe below uses a CANONICAL-shaped spoof. The probe
    // runs on its OWN scoped token so a refused request cannot disturb the main token's state.
    let probe_issue_chirho = oauth_chirho::issue_scoped_token_chirho(
        &setup_chirho.root_chirho,
        payer_chirho,
        &setup_chirho.payer_credential_chirho,
        &setup_chirho.oauth_client_id_chirho,
        vec!["invoke_chirho".to_string()],
    )?;
    let probe_bearer_chirho = format!("Bearer {}", probe_issue_chirho.token_chirho);
    let malformed_body_chirho = format!(
        "item_chirho={}&concurrency_token_chirho=malformed-token-chirho&user_principal_chirho={}",
        constants_chirho::SPEND_ITEM_CHIRHO,
        MALFORMED_ATTACKER_PRINCIPAL_CHIRHO,
    );
    let malformed_chirho = try_http_request_chirho(
        addr_chirho,
        "POST",
        SPEND_PATH_CHIRHO,
        &[
            ("authorization", &probe_bearer_chirho),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        malformed_body_chirho.as_bytes(),
    )?;
    if malformed_chirho.status_chirho == 200 {
        bail!("malformed spend probe was served (expected an input-validation refusal)");
    }

    // L1: authenticated balance is 750, fresh, exactly the viewer's row, never settlement's.
    let l1_response_chirho = try_http_request_chirho(
        addr_chirho,
        "GET",
        BALANCE_PATH_CHIRHO,
        &[("authorization", &bearer_chirho)],
        &[],
    )?;
    let l1_chirho =
        viewer_scope_evidence_chirho("GET", &l1_response_chirho, payer_chirho, settlement_chirho);
    if l1_chirho.status_chirho != 200
        || l1_chirho.parsed_balance_chirho != Some(750)
        || !l1_chirho.fresh_chirho
    {
        let body_excerpt_chirho: String = l1_response_chirho
            .body_text_chirho()
            .chars()
            .take(300)
            .collect();
        bail!(
            "L1 balance was not 750 fresh: status={} parsed={:?} body[..300]={body_excerpt_chirho}",
            l1_chirho.status_chirho,
            l1_chirho.parsed_balance_chirho
        );
    }
    if l1_chirho.viewer_rows_chirho != 1
        || l1_chirho.settlement_rows_in_body_chirho != 0
        || l1_chirho.viewer_principal_occurrences_chirho != 1
    {
        bail!("L1 balance was not exactly the authenticated payer's own row (#6061)");
    }
    let balances_l1_chirho = host_chirho.read_substrate_balances_chirho()?;
    snapshots_chirho.push(snapshot_cut_chirho("L1", &balances_l1_chirho));
    let l1_seq_chirho = balances_l1_chirho.tail_seq_chirho;
    let balance_l1_chirho = account_net_chirho(&balances_l1_chirho, payer_chirho, kind_chirho);
    if balance_l1_chirho != 750 {
        bail!("L1 verified payer net was {balance_l1_chirho}, expected 750");
    }

    // L2: hostile body (amount=999 + CANONICAL-shaped spoof principal) → the verified session
    // payer is charged EXACTLY the signed price (10), not 999, and never the spoof.
    let hostile_body_chirho = format!(
        "item_chirho={}&concurrency_token_chirho={}&amount_chirho=999&user_principal_chirho={}",
        constants_chirho::SPEND_ITEM_CHIRHO,
        setup_chirho.l2_spend_token_chirho,
        ATTACKER_PRINCIPAL_CHIRHO,
    );
    let l2_response_chirho = try_http_request_chirho(
        addr_chirho,
        "POST",
        SPEND_PATH_CHIRHO,
        &[
            ("authorization", &bearer_chirho),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        hostile_body_chirho.as_bytes(),
    )?;
    let l2_text_chirho = l2_response_chirho.body_text_chirho();
    let committed_chirho = l2_response_chirho.status_chirho == 200
        && l2_text_chirho.contains("spend-committed-chirho");
    if !committed_chirho {
        bail!(
            "L2 spend was not committed: status={} body={l2_text_chirho}",
            l2_response_chirho.status_chirho
        );
    }
    let balances_after_l2_chirho = host_chirho.read_substrate_balances_chirho()?;
    snapshots_chirho.push(snapshot_cut_chirho("after-L2", &balances_after_l2_chirho));
    let balance_after_l2_chirho =
        account_net_chirho(&balances_after_l2_chirho, payer_chirho, kind_chirho);
    let settlement_after_l2_chirho =
        account_net_chirho(&balances_after_l2_chirho, settlement_chirho, kind_chirho);
    let expected_after_l2_chirho = balance_l1_chirho
        .checked_sub(10)
        .ok_or_else(|| anyhow::anyhow!("L1 balance under the signed price"))?;
    let payer_charged_price_chirho =
        balance_after_l2_chirho == expected_after_l2_chirho && settlement_after_l2_chirho == 10;
    if !payer_charged_price_chirho {
        bail!(
            "L2 charge was not exactly the signed price: payer {balance_l1_chirho}->{balance_after_l2_chirho}, settlement {settlement_after_l2_chirho}"
        );
    }
    let l2_tail_advanced_chirho =
        balances_after_l2_chirho.tail_seq_chirho > balances_l1_chirho.tail_seq_chirho;
    if account_held_chirho(&balances_after_l2_chirho, payer_chirho, kind_chirho) != 0 {
        bail!("L2 left a nonzero payer held escrow");
    }
    // The CANONICAL-shaped spoofed principal must have NO account in the AUTHORITATIVE ledger —
    // the engine neither created nor debited it (keyed by the exact constant, full-string).
    let attacker_net_chirho = account_net_chirho(
        &balances_after_l2_chirho,
        ATTACKER_PRINCIPAL_CHIRHO,
        kind_chirho,
    );
    let attacker_absent_from_map_chirho = !balances_after_l2_chirho
        .account_nets_chirho
        .keys()
        .any(|(owner_chirho, _kind_chirho)| owner_chirho == ATTACKER_PRINCIPAL_CHIRHO);
    let attacker_account_absent_or_uncharged_chirho =
        attacker_absent_from_map_chirho && attacker_net_chirho == 0;
    if !attacker_account_absent_or_uncharged_chirho {
        bail!("L2 created or charged a spoof account from the hostile body");
    }
    // The response must echo neither spoof (FULL prefixed strings, #6055) nor the hostile amount.
    let hostile_body_ignored_chirho = !l2_text_chirho.contains(ATTACKER_PRINCIPAL_CHIRHO)
        && !l2_text_chirho.contains(MALFORMED_ATTACKER_PRINCIPAL_CHIRHO)
        && !l2_text_chirho.contains("999");
    let l2_chirho = SpendEvidenceChirho {
        method_chirho: "POST".to_string(),
        path_chirho: SPEND_PATH_CHIRHO.to_string(),
        status_chirho: l2_response_chirho.status_chirho,
        body_chirho: cas_chirho::hash_chirho(&l2_response_chirho.body_chirho),
        committed_chirho,
        hostile_body_ignored_chirho,
        verified_payer_charged_exactly_price_chirho: payer_charged_price_chirho,
        balance_before_chirho: balance_l1_chirho,
        balance_after_chirho: balance_after_l2_chirho,
        settlement_after_chirho: settlement_after_l2_chirho,
        single_signed_price_charge_chirho: payer_charged_price_chirho,
        journal_tail_advanced_chirho: l2_tail_advanced_chirho,
        attacker_account_absent_or_uncharged_chirho,
    };

    // Same-K replay: byte-identical response, no double charge, no new hold, and the FULL journal
    // cut tuple (seq + tail-line digest) unchanged (#6050 HOLD B — a seq alone is not a cut).
    let replay_response_chirho = try_http_request_chirho(
        addr_chirho,
        "POST",
        SPEND_PATH_CHIRHO,
        &[
            ("authorization", &bearer_chirho),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        hostile_body_chirho.as_bytes(),
    )?;
    let balances_after_replay_chirho = host_chirho.read_substrate_balances_chirho()?;
    snapshots_chirho.push(snapshot_cut_chirho(
        "after-replay",
        &balances_after_replay_chirho,
    ));
    let byte_identical_chirho = replay_response_chirho.body_chirho
        == l2_response_chirho.body_chirho
        && replay_response_chirho.status_chirho == l2_response_chirho.status_chirho;
    let replay_net_chirho =
        account_net_chirho(&balances_after_replay_chirho, payer_chirho, kind_chirho);
    let replay_settlement_chirho = account_net_chirho(
        &balances_after_replay_chirho,
        settlement_chirho,
        kind_chirho,
    );
    let no_double_charge_chirho = replay_net_chirho == balance_after_l2_chirho
        && replay_settlement_chirho == settlement_after_l2_chirho;
    let no_new_hold_chirho =
        account_held_chirho(&balances_after_replay_chirho, payer_chirho, kind_chirho) == 0;
    let journal_cut_unchanged_chirho = balances_after_replay_chirho.tail_seq_chirho
        == balances_after_l2_chirho.tail_seq_chirho
        && balances_after_replay_chirho.tail_line_digest_chirho
            == balances_after_l2_chirho.tail_line_digest_chirho
        && balances_after_replay_chirho.genesis_digest_chirho
            == balances_after_l2_chirho.genesis_digest_chirho;
    if !byte_identical_chirho || !no_double_charge_chirho || !journal_cut_unchanged_chirho {
        bail!("same-K replay was not idempotent (byte/charge/cut)");
    }
    let replay_chirho = ReplayEvidenceChirho {
        status_chirho: replay_response_chirho.status_chirho,
        body_chirho: cas_chirho::hash_chirho(&replay_response_chirho.body_chirho),
        byte_identical_response_chirho: byte_identical_chirho,
        no_double_charge_chirho,
        no_new_hold_chirho,
        journal_cut_unchanged_chirho,
        balance_after_chirho: replay_net_chirho,
        settlement_after_chirho: replay_settlement_chirho,
    };

    // Distinct-K retry: the DERIVED distinct valid 64-hex token on the now-absent row → definite
    // no effect; the journal appends a net-zero Hold→Release pair (tail +2) with no money moved
    // and held back to 0.
    let distinct_body_chirho = format!(
        "item_chirho={}&concurrency_token_chirho={}",
        constants_chirho::SPEND_ITEM_CHIRHO,
        setup_chirho
            .external_preconditions_chirho
            .r4b_distinct_token_chirho,
    );
    let r4b_response_chirho = try_http_request_chirho(
        addr_chirho,
        "POST",
        SPEND_PATH_CHIRHO,
        &[
            ("authorization", &bearer_chirho),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        distinct_body_chirho.as_bytes(),
    )?;
    let r4b_text_chirho = r4b_response_chirho.body_text_chirho();
    let definite_no_effect_chirho = r4b_response_chirho.status_chirho == 200
        && r4b_text_chirho.contains("spend-no-effect-chirho");
    if !definite_no_effect_chirho {
        bail!("R4b distinct-K retry was not definite-no-effect: body={r4b_text_chirho}");
    }
    let balances_after_r4b_chirho = host_chirho.read_substrate_balances_chirho()?;
    snapshots_chirho.push(snapshot_cut_chirho("after-R4b", &balances_after_r4b_chirho));
    let r4b_net_chirho = account_net_chirho(&balances_after_r4b_chirho, payer_chirho, kind_chirho);
    let r4b_settlement_chirho =
        account_net_chirho(&balances_after_r4b_chirho, settlement_chirho, kind_chirho);
    let net_money_unchanged_chirho = r4b_net_chirho == balance_after_l2_chirho
        && r4b_settlement_chirho == settlement_after_l2_chirho;
    let payer_held_zero_chirho =
        account_held_chirho(&balances_after_r4b_chirho, payer_chirho, kind_chirho) == 0;
    let expected_r4b_tail_chirho = balances_after_replay_chirho
        .tail_seq_chirho
        .checked_add(2)
        .ok_or_else(|| anyhow::anyhow!("replay tail seq overflow"))?;
    let tail_advanced_by_two_chirho =
        balances_after_r4b_chirho.tail_seq_chirho == expected_r4b_tail_chirho;
    let pg_values_row_count_chirho = pg_values_row_count_chirho(&setup_chirho.dsn_chirho)?;
    if !net_money_unchanged_chirho || !payer_held_zero_chirho || !tail_advanced_by_two_chirho {
        bail!("R4b did not append a net-zero Hold->Release pair with held 0 and money unchanged");
    }
    if pg_values_row_count_chirho != 0 {
        bail!("R4b PG values row count was {pg_values_row_count_chirho}, expected 0 (row deleted at L2)");
    }
    let r4b_chirho = DistinctRetryEvidenceChirho {
        status_chirho: r4b_response_chirho.status_chirho,
        body_chirho: cas_chirho::hash_chirho(&r4b_response_chirho.body_chirho),
        definite_no_effect_chirho,
        no_amplification_chirho: net_money_unchanged_chirho,
        payer_held_zero_chirho,
        journal_tail_advanced_by_two_chirho: tail_advanced_by_two_chirho,
        net_money_unchanged_chirho,
        balance_after_chirho: r4b_net_chirho,
        settlement_after_chirho: r4b_settlement_chirho,
        pg_values_row_count_chirho,
    };

    Ok(Phase1OutcomeChirho {
        anonymous_refusal_chirho,
        l1_chirho,
        l1_seq_chirho,
        session_token_chirho: issue_chirho.token_chirho.clone(),
        probe_session_token_chirho: probe_issue_chirho.token_chirho.clone(),
        l2_chirho,
        replay_chirho,
        r4b_chirho,
        balance_l1_chirho,
        balance_after_l2_chirho,
        settlement_after_l2_chirho,
        served_viewer_principal_chirho,
        snapshots_chirho,
    })
}

struct CompensationOutcomeChirho {
    evidence_chirho: CompensationEvidenceChirho,
    before_snapshot_chirho: SnapshotCutChirho,
}

fn drive_compensation_chirho(
    pg_chirho: &SharedLedgerHostPostgresEffectRuntimeChirho,
    host_chirho: &LedgerHostProjectionReadPortChirho,
    setup_chirho: &CreditsDemoSetupChirho,
    payer_chirho: &str,
    settlement_chirho: &str,
    kind_chirho: &str,
) -> Result<CompensationOutcomeChirho> {
    let before_chirho = host_chirho.read_substrate_balances_chirho()?;
    let before_snapshot_chirho = snapshot_cut_chirho("before-compensation", &before_chirho);
    let payer_before_chirho = account_net_chirho(&before_chirho, payer_chirho, kind_chirho);
    let settlement_before_chirho =
        account_net_chirho(&before_chirho, settlement_chirho, kind_chirho);

    let preview_chirho = preview_current_ledger_host_postgres_compensation_chirho(
        pg_chirho,
        &setup_chirho.root_chirho,
        constants_chirho::APP_CHIRHO,
        &setup_chirho.owner_chirho,
    )?;
    let executable_chirho = matches!(
        preview_chirho.verdict_chirho,
        CurrentPostgresCompensationPreviewVerdictChirho::ExecutableChirho
    );
    let bound_to_reviewed_report_chirho =
        preview_chirho.source_review_report_chirho.0 == setup_chirho.source_review_report_chirho;
    if !executable_chirho {
        bail!("compensation preview verdict was not executable");
    }
    if !bound_to_reviewed_report_chirho {
        bail!("compensation preview did not bind the reviewed source-review report");
    }

    let execution_chirho = execute_current_ledger_host_postgres_compensation_chirho(
        pg_chirho,
        &setup_chirho.root_chirho,
        constants_chirho::APP_CHIRHO,
        &setup_chirho.owner_chirho,
    )?;
    let committed_chirho = matches!(
        execution_chirho.disposition_chirho,
        EffectTerminalDispositionChirho::CommittedChirho { .. }
    );
    if !committed_chirho || !execution_chirho.provider_restored_chirho {
        bail!("compensation did not commit with provider restored");
    }

    let after_chirho = host_chirho.read_substrate_balances_chirho()?;
    let payer_after_chirho = account_net_chirho(&after_chirho, payer_chirho, kind_chirho);
    let settlement_after_chirho = account_net_chirho(&after_chirho, settlement_chirho, kind_chirho);
    let payer_held_zero_chirho = account_held_chirho(&after_chirho, payer_chirho, kind_chirho) == 0;
    // NO refund: the compensation is a compensating charge (another price debit + settlement credit),
    // never a refund of the original — payer falls another 10, settlement rises another 10.
    let expected_payer_after_chirho = payer_before_chirho
        .checked_sub(10)
        .ok_or_else(|| anyhow::anyhow!("payer net under the compensation price"))?;
    let expected_settlement_after_chirho = settlement_before_chirho
        .checked_add(10)
        .ok_or_else(|| anyhow::anyhow!("settlement net overflow"))?;
    let no_refund_chirho = payer_after_chirho == expected_payer_after_chirho
        && settlement_after_chirho == expected_settlement_after_chirho;
    if !no_refund_chirho {
        bail!(
            "compensation was not no-refund: payer {payer_before_chirho}->{payer_after_chirho}, settlement {settlement_before_chirho}->{settlement_after_chirho}"
        );
    }
    if !payer_held_zero_chirho {
        bail!("compensation left a nonzero payer held escrow");
    }
    let comp_receipt_count_chirho = pg_comp_receipt_count_chirho(&setup_chirho.dsn_chirho)?;
    let pg_values_row_count_chirho = pg_values_row_count_chirho(&setup_chirho.dsn_chirho)?;
    if comp_receipt_count_chirho != 1 {
        bail!("compensation receipt count was {comp_receipt_count_chirho}, expected 1");
    }
    if pg_values_row_count_chirho != 1 {
        bail!("compensation did not restore the provider row (values count {pg_values_row_count_chirho}, expected 1)");
    }

    Ok(CompensationOutcomeChirho {
        evidence_chirho: CompensationEvidenceChirho {
            preview_verdict_executable_chirho: executable_chirho,
            source_review_report_chirho: preview_chirho.source_review_report_chirho.0,
            bound_to_reviewed_report_chirho,
            undo_plan_digest_chirho: preview_chirho.plan_digest_chirho.0,
            committed_chirho,
            provider_restored_chirho: execution_chirho.provider_restored_chirho,
            comp_receipt_count_chirho,
            pg_values_row_count_chirho,
            payer_held_zero_chirho,
            no_refund_chirho,
            payer_net_after_chirho: payer_after_chirho,
            settlement_net_after_chirho: settlement_after_chirho,
        },
        before_snapshot_chirho,
    })
}

fn drive_l5_chirho(
    addr_chirho: &str,
    setup_chirho: &CreditsDemoSetupChirho,
    payer_chirho: &str,
    settlement_chirho: &str,
) -> Result<(ViewerScopeEvidenceChirho, String)> {
    wait_for_serve_health_chirho(addr_chirho)?;
    let issue_chirho = oauth_chirho::issue_scoped_token_chirho(
        &setup_chirho.root_chirho,
        payer_chirho,
        &setup_chirho.payer_credential_chirho,
        &setup_chirho.oauth_client_id_chirho,
        vec!["invoke_chirho".to_string()],
    )?;
    // The SECOND issuance must authenticate the same payer (#6071) — the L5 leg's token is not
    // assumed to bind the phase-1 principal.
    if issue_chirho.record_chirho.principal_chirho != payer_chirho {
        bail!("L5 scoped token principal does not equal the payer");
    }
    let bearer_chirho = format!("Bearer {}", issue_chirho.token_chirho);
    let response_chirho = try_http_request_chirho(
        addr_chirho,
        "GET",
        BALANCE_PATH_CHIRHO,
        &[("authorization", &bearer_chirho)],
        &[],
    )?;
    let evidence_chirho =
        viewer_scope_evidence_chirho("GET", &response_chirho, payer_chirho, settlement_chirho);
    if evidence_chirho.status_chirho != 200
        || evidence_chirho.parsed_balance_chirho != Some(730)
        || !evidence_chirho.fresh_chirho
    {
        let body_excerpt_chirho: String = response_chirho
            .body_text_chirho()
            .chars()
            .take(300)
            .collect();
        bail!(
            "L5 balance was not 730 fresh: status={} parsed={:?} body[..300]={body_excerpt_chirho}",
            evidence_chirho.status_chirho,
            evidence_chirho.parsed_balance_chirho
        );
    }
    if evidence_chirho.viewer_rows_chirho != 1
        || evidence_chirho.settlement_rows_in_body_chirho != 0
        || evidence_chirho.viewer_principal_occurrences_chirho != 1
    {
        bail!(
            "L5 balance was not exactly the authenticated payer's own row post-settlement (#6061)"
        );
    }
    Ok((evidence_chirho, issue_chirho.token_chirho))
}
