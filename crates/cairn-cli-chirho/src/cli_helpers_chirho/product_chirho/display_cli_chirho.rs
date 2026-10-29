// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Text display helpers for CLI listing commands.

use cairn_chirho::realtime_legacy_evidence_chirho;
use cairn_ledger_host_chirho::reconciliation_chirho::{
    dispose_gd7_obligation_held_manual_chirho, load_gd7_obligation_processing_for_display_chirho,
    load_gd7_obligation_processing_state_chirho, write_gd7_operator_roster_chirho,
    ExistingNodeGd7SignerChirho, Gd7HeldManualDispositionChirho, Gd7OperatorRosterChirho,
    PinnedNodeGd7VerifierChirho,
};
use cairn_ledger_host_chirho::FsLedgerStorageChirho;
use std::path::Path;

pub(crate) fn handle_gd7_obligation_processing_list_chirho(
    root_chirho: &Path,
) -> anyhow::Result<bool> {
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(root_chirho)?;
    let records_chirho = load_gd7_obligation_processing_for_display_chirho(&storage_chirho)?;
    for record_chirho in records_chirho {
        let status_chirho = if record_chirho.valid_chirho {
            "VALID"
        } else {
            "INVALID"
        };
        let detail_chirho = record_chirho
            .validation_error_chirho
            .as_deref()
            .unwrap_or("ok");
        let progress_chirho = record_chirho
            .state_chirho
            .as_ref()
            .map(|state_chirho| format!("{:?}", state_chirho.terminal_progress_chirho()))
            .unwrap_or_else(|| "UnavailableChirho".to_owned());
        println!(
            "{}\t{}\t{}\t{}",
            status_chirho, progress_chirho, record_chirho.path_chirho, detail_chirho
        );
    }
    Ok(true)
}

pub(crate) fn handle_gd7_operator_roster_set_chirho(
    root_chirho: &Path,
    group_digest_chirho: &str,
    signer_key_id_chirho: &str,
    roster_path_chirho: &Path,
) -> anyhow::Result<bool> {
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(root_chirho)?;
    let roster_bytes_chirho = std::fs::read(roster_path_chirho)?;
    let roster_chirho: Gd7OperatorRosterChirho = serde_json::from_slice(&roster_bytes_chirho)?;
    let signer_chirho = ExistingNodeGd7SignerChirho::open_existing_with_key_id_chirho(
        root_chirho,
        signer_key_id_chirho,
    )?;
    let written_chirho = write_gd7_operator_roster_chirho(
        &storage_chirho,
        group_digest_chirho,
        &signer_chirho,
        roster_chirho,
    )?;
    println!(
        "gd7-operator-roster-set\t{}",
        written_chirho.roster_epoch_chirho
    );
    Ok(true)
}

pub(crate) fn handle_gd7_obligation_processing_dispose_chirho(
    root_chirho: &Path,
    mint_identity_chirho: &str,
    operator_key_id_chirho: &str,
    disposition_path_chirho: &Path,
) -> anyhow::Result<bool> {
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(root_chirho)?;
    let state_chirho =
        load_gd7_obligation_processing_state_chirho(&storage_chirho, mint_identity_chirho)?;
    let disposition_bytes_chirho = std::fs::read(disposition_path_chirho)?;
    let disposition_chirho: Gd7HeldManualDispositionChirho =
        serde_json::from_slice(&disposition_bytes_chirho)?;
    let verifier_chirho =
        PinnedNodeGd7VerifierChirho::new_from_key_id_chirho(operator_key_id_chirho.to_owned())?;
    dispose_gd7_obligation_held_manual_chirho(
        &storage_chirho,
        &state_chirho,
        disposition_chirho,
        &verifier_chirho,
    )?;
    println!("disposed\t{}", mint_identity_chirho);
    Ok(true)
}

pub(crate) fn realtime_sessions_list_text_chirho(
    records_chirho: &[realtime_legacy_evidence_chirho::RealtimeSessionDisplayRecordChirho],
) -> String {
    let mut out_chirho = String::new();
    for record_chirho in records_chirho {
        let status_chirho = if record_chirho.valid_chirho() {
            "VALID"
        } else {
            "INVALID"
        };
        if let Some(raw_record_chirho) = &record_chirho.record_chirho {
            out_chirho.push_str(&format!(
                "#{}\t{}\t{}\t{:?}\tcaller={}\tpayer={}\tprovider={}\tauthorized_token={} settled={} released={} transcript={}",
                raw_record_chirho.seq_chirho,
                status_chirho,
                raw_record_chirho.session_id_chirho,
                raw_record_chirho.status_chirho,
                raw_record_chirho.caller_chirho,
                raw_record_chirho.payer_chirho,
                raw_record_chirho.provider_account_chirho,
                raw_record_chirho.authorized_token_chirho,
                raw_record_chirho.settled_token_chirho,
                raw_record_chirho.released_token_chirho,
                raw_record_chirho
                    .transcript_chirho
                    .as_ref()
                    .map(|hash_chirho| hash_chirho.0.as_str())
                    .unwrap_or("(none)")
            ));
        } else {
            out_chirho.push_str(&format!(
                "line={}\t{}\tunparseable realtime session record",
                record_chirho.line_chirho, status_chirho
            ));
        }
        if let Some(error_chirho) = &record_chirho.validation_error_chirho {
            out_chirho.push_str(&format!("\tvalidation_error={error_chirho}"));
        }
        out_chirho.push('\n');
    }
    out_chirho
}

pub(crate) fn realtime_events_list_text_chirho(
    records_chirho: &[realtime_legacy_evidence_chirho::RealtimeEventDisplayRecordChirho],
) -> String {
    let mut out_chirho = String::new();
    for record_chirho in records_chirho {
        let status_chirho = if record_chirho.valid_chirho() {
            "VALID"
        } else {
            "INVALID"
        };
        if let Some(raw_record_chirho) = &record_chirho.record_chirho {
            out_chirho.push_str(&format!(
                "#{}\t{}\t{}\t{:?}\tseconds={}\ttoken={}\tledger={:?}\tpayload={}",
                raw_record_chirho.seq_chirho,
                status_chirho,
                raw_record_chirho.session_id_chirho,
                raw_record_chirho.kind_chirho,
                raw_record_chirho.billable_seconds_chirho,
                raw_record_chirho.amount_token_chirho,
                raw_record_chirho.ledger_seq_chirho,
                raw_record_chirho.payload_chirho.ciphertext_chirho.0
            ));
        } else {
            out_chirho.push_str(&format!(
                "line={}\t{}\tunparseable realtime event record",
                record_chirho.line_chirho, status_chirho
            ));
        }
        if let Some(error_chirho) = &record_chirho.validation_error_chirho {
            out_chirho.push_str(&format!("\tvalidation_error={error_chirho}"));
        }
        out_chirho.push('\n');
    }
    out_chirho
}

pub(crate) fn realtime_epilogues_list_text_chirho(
    records_chirho: &[realtime_legacy_evidence_chirho::RealtimeEpilogueDisplayRecordChirho],
) -> String {
    let mut out_chirho = String::new();
    for record_chirho in records_chirho {
        let status_chirho = if record_chirho.valid_chirho() {
            "VALID"
        } else {
            "INVALID"
        };
        if let Some(raw_record_chirho) = &record_chirho.record_chirho {
            out_chirho.push_str(&format!(
                "#{}\t{}\tsession={}\tapp={}\tartifact={}\tdag={}\tsink_run={}\tpayload={}\tnodes={}",
                raw_record_chirho.seq_chirho,
                status_chirho,
                raw_record_chirho.session_id_chirho,
                raw_record_chirho.app_chirho,
                raw_record_chirho.artifact_chirho.0,
                raw_record_chirho.dag_chirho.0,
                raw_record_chirho.sink_run_chirho.0,
                raw_record_chirho.payload_hash_chirho.0,
                raw_record_chirho.node_runs_chirho.len()
            ));
        } else {
            out_chirho.push_str(&format!(
                "line={}\t{}\tunparseable realtime epilogue record",
                record_chirho.line_chirho, status_chirho
            ));
        }
        if let Some(error_chirho) = &record_chirho.validation_error_chirho {
            out_chirho.push_str(&format!("\tvalidation_error={error_chirho}"));
        }
        out_chirho.push('\n');
    }
    out_chirho
}
