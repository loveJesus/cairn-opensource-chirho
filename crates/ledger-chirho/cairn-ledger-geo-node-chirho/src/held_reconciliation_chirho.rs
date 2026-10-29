// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Restart-stable held-side driver from a frozen losing tail through `PlanSealed`.
//!
//! Each accepted coordinator command advances at most one bounded page. The driver therefore uses
//! O(page) memory even though total recovery work must remain proportional to the divergent suffix.
//! It imports evidence and seals a plan only; it cannot adopt, compensate, move refs, append ledger
//! records, or enable writes.

use super::winner_fork_observation_chirho::{
    call_winner_fork_observation_chirho, Gd7WinnerForkObservationCallContextChirho,
};
use anyhow::{anyhow, bail, Context, Result};
use cairn_ledger_host_chirho::reconciliation_chirho::{
    ExistingNodeGd7SignerChirho, Gd7JournalTailCoordinateChirho, Gd7ReconciliationPhaseChirho,
};
use cairn_ledger_host_chirho::{
    ResidentGd7HeldBootstrapSnapshotChirho, ResidentGd7HeldCoordinatorHandleChirho,
    ResidentGd7HeldSealedPlanSnapshotChirho,
};
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use serde_json::json;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const GD7_HELD_OBSERVATION_REQUEST_TIMEOUT_CHIRHO: Duration = Duration::from_secs(2);
const GD7_HELD_OBSERVATION_RETRY_WINDOW_CHIRHO: Duration = Duration::from_secs(30);
const GD7_HELD_OBSERVATION_RETRY_DELAY_CHIRHO: Duration = Duration::from_millis(100);

pub(super) fn drive_held_reconciliation_chirho(
    selected_root_chirho: &Path,
    winner_base_url_chirho: &str,
    coordinator_chirho: &ResidentGd7HeldCoordinatorHandleChirho,
    stop_chirho: &AtomicBool,
) -> Result<ResidentGd7HeldSealedPlanSnapshotChirho> {
    let bootstrap_chirho = coordinator_chirho
        .bootstrap_chirho()
        .context("inspect exact held bootstrap coordinate")?;
    let mut active_chirho = match bootstrap_chirho.active_checkpoint_ref_chirho.as_ref() {
        Some(_checkpoint_ref_chirho) => coordinator_chirho
            .inspect_chirho()
            .context("reload existing held reconciliation checkpoint")?,
        None => {
            let held_node_chirho = NodeIdChirho(bootstrap_chirho.held_node_chirho.clone());
            let held_signer_chirho = ExistingNodeGd7SignerChirho::open_existing_chirho(
                selected_root_chirho,
                &held_node_chirho,
            )
            .context("open existing held observation signer")?;
            let agent_chirho = ureq::AgentBuilder::new()
                .timeout(GD7_HELD_OBSERVATION_REQUEST_TIMEOUT_CHIRHO)
                .build();
            let request_nonce_chirho = observation_nonce_chirho(&bootstrap_chirho)?;
            let import_chirho = request_observation_with_retry_chirho(
                &agent_chirho,
                winner_base_url_chirho,
                coordinator_chirho,
                &bootstrap_chirho,
                &held_signer_chirho,
                &request_nonce_chirho,
                stop_chirho,
            )?;
            require_exact_bootstrap_chirho(coordinator_chirho, &bootstrap_chirho)?;
            coordinator_chirho
                .install_authenticated_observation_chirho(import_chirho)
                .context("verify and install authenticated winner observation")?
        }
    };

    loop {
        if stop_chirho.load(Ordering::Acquire) {
            bail!("held reconciliation stopped before its plan sealed");
        }
        if active_chirho.phase_chirho == Gd7ReconciliationPhaseChirho::PlanSealedChirho {
            return coordinator_chirho
                .verify_sealed_plan_chirho(active_chirho.checkpoint_ref_chirho)
                .context("reverify complete sealed held reconciliation plan");
        }
        let prior_checkpoint_ref_chirho = active_chirho.checkpoint_ref_chirho.clone();
        active_chirho = coordinator_chirho
            .advance_one_page_chirho(prior_checkpoint_ref_chirho.clone())
            .context("advance one bounded held reconciliation page")?;
        if active_chirho.checkpoint_ref_chirho == prior_checkpoint_ref_chirho
            && active_chirho.phase_chirho != Gd7ReconciliationPhaseChirho::PlanSealedChirho
        {
            bail!("held reconciliation made no durable page progress");
        }
    }
}

fn request_observation_with_retry_chirho(
    agent_chirho: &ureq::Agent,
    winner_base_url_chirho: &str,
    coordinator_chirho: &ResidentGd7HeldCoordinatorHandleChirho,
    bootstrap_chirho: &ResidentGd7HeldBootstrapSnapshotChirho,
    held_signer_chirho: &ExistingNodeGd7SignerChirho,
    request_nonce_chirho: &str,
    stop_chirho: &AtomicBool,
) -> Result<cairn_ledger_host_chirho::ResidentGd7HeldObservationImportChirho> {
    let deadline_chirho = Instant::now() + GD7_HELD_OBSERVATION_RETRY_WINDOW_CHIRHO;
    let mut last_error_chirho = None;
    while Instant::now() < deadline_chirho && !stop_chirho.load(Ordering::Acquire) {
        require_exact_bootstrap_chirho(coordinator_chirho, bootstrap_chirho)?;
        let result_chirho =
            call_winner_fork_observation_chirho(Gd7WinnerForkObservationCallContextChirho {
                agent_chirho,
                base_url_chirho: winner_base_url_chirho,
                consistency_group_digest_chirho: &bootstrap_chirho.consistency_group_digest_chirho,
                held_signer_chirho,
                winner_node_chirho: &NodeIdChirho(bootstrap_chirho.winner_node_chirho.clone()),
                expected_winner_term_chirho: bootstrap_chirho.winner_term_chirho,
                losing_journal_genesis_digest_chirho: &bootstrap_chirho
                    .losing_journal_genesis_digest_chirho,
                losing_journal_tail_chirho: &Gd7JournalTailCoordinateChirho {
                    epoch_chirho: bootstrap_chirho.losing_tail_epoch_chirho,
                    seq_chirho: bootstrap_chirho.losing_tail_seq_chirho,
                    record_digest_chirho: bootstrap_chirho.losing_tail_digest_chirho.clone(),
                },
                request_nonce_chirho,
            });
        match result_chirho {
            Ok(import_chirho) => return Ok(import_chirho),
            Err(error_chirho) => last_error_chirho = Some(error_chirho),
        }
        std::thread::sleep(GD7_HELD_OBSERVATION_RETRY_DELAY_CHIRHO);
    }
    if stop_chirho.load(Ordering::Acquire) {
        bail!("held reconciliation stopped during winner observation");
    }
    Err(last_error_chirho.unwrap_or_else(|| anyhow!("winner observation retry window elapsed")))
        .context("winner observation did not become available within the bounded retry window")
}

fn require_exact_bootstrap_chirho(
    coordinator_chirho: &ResidentGd7HeldCoordinatorHandleChirho,
    expected_chirho: &ResidentGd7HeldBootstrapSnapshotChirho,
) -> Result<()> {
    let actual_chirho = coordinator_chirho
        .bootstrap_chirho()
        .context("revalidate held bootstrap coordinate")?;
    if &actual_chirho != expected_chirho {
        bail!("held bootstrap coordinate changed around winner observation");
    }
    Ok(())
}

fn observation_nonce_chirho(
    bootstrap_chirho: &ResidentGd7HeldBootstrapSnapshotChirho,
) -> Result<String> {
    let bytes_chirho = serde_json::to_vec(&json!({
        "schema_chirho": "gd7-held-observation-nonce-v1-chirho",
        "consistency_group_digest_chirho": bootstrap_chirho.consistency_group_digest_chirho,
        "winner_node_chirho": bootstrap_chirho.winner_node_chirho,
        "held_node_chirho": bootstrap_chirho.held_node_chirho,
        "winner_term_chirho": bootstrap_chirho.winner_term_chirho,
        "losing_journal_genesis_digest_chirho":
            bootstrap_chirho.losing_journal_genesis_digest_chirho,
        "losing_tail_epoch_chirho": bootstrap_chirho.losing_tail_epoch_chirho,
        "losing_tail_seq_chirho": bootstrap_chirho.losing_tail_seq_chirho,
        "losing_tail_digest_chirho": bootstrap_chirho.losing_tail_digest_chirho,
    }))
    .context("encode deterministic held observation nonce")?;
    Ok(blake3::hash(&bytes_chirho).to_hex().to_string())
}
