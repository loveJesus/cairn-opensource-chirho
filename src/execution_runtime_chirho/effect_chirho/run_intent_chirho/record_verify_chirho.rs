// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The run-intent log's per-record checks and its whole-log verification: the rules the operator verifier and the
//! admission view (checkpoint brick S3) both run, kept in one place so the two cannot drift apart.

use super::*;

pub fn verify_run_intent_records_chirho(root_chirho: &Path) -> Result<usize> {
    let records_chirho = load_run_intent_records_chirho(root_chirho)?;
    if records_chirho.is_empty() {
        return Ok(0);
    }
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    // ONE resolver for the whole pass. Asking the single-pair function once per record re-read the
    // whole private-value log, the whole privacy blob log and every shred-key file per record; the
    // resolver reads each once, verifies each request value once, and gives the same verdicts.
    let mut private_values_chirho =
        crate::dag_private_value_chirho::PrivateDagValueSubjectResolverChirho::new_chirho(
            root_chirho,
        );
    let mut last_by_run_chirho = std::collections::BTreeMap::<HashChirho, String>::new();
    for (idx_chirho, record_chirho) in records_chirho.iter().enumerate() {
        verify_run_intent_record_chirho(
            root_chirho,
            &pubkey_chirho,
            &mut private_values_chirho,
            idx_chirho,
            record_chirho,
        )?;
        let previous_chirho = last_by_run_chirho.insert(
            record_chirho.run_chirho.clone(),
            record_chirho.status_chirho.clone(),
        );
        verify_run_intent_transition_chirho(record_chirho, previous_chirho.as_deref())?;
    }
    Ok(records_chirho.len())
}

pub(super) fn verify_run_intent_record_chirho(
    root_chirho: &Path,
    pubkey_chirho: &str,
    private_values_chirho: &mut crate::dag_private_value_chirho::PrivateDagValueSubjectResolverChirho,
    idx_chirho: usize,
    record_chirho: &RunIntentRecordChirho,
) -> Result<()> {
    match (
        record_chirho.schema_chirho.as_str(),
        record_chirho.caller_idempotency_key_digest_chirho.is_some(),
        record_chirho.caller_operation_digest_chirho.is_some(),
    ) {
        (RUN_INTENT_RECORD_SCHEMA_CHIRHO, false, false)
        | (RUN_INTENT_RECORD_SCHEMA_V2_CHIRHO, true, false)
        | (RUN_INTENT_RECORD_SCHEMA_V3_CHIRHO, true, true) => {}
        _ => {
            bail!(
                "run intent record {idx_chirho} has unsupported schema, caller-key, or operation shape"
            )
        }
    }
    if record_chirho.seq_chirho != idx_chirho as u64 {
        bail!("run intent record seq gap at index {idx_chirho}");
    }
    if !valid_status_chirho(&record_chirho.status_chirho) {
        bail!("run intent record {idx_chirho} has invalid status");
    }
    verify_error_fields_chirho(record_chirho, idx_chirho)?;
    let expected_context_chirho = run_intent_context_hash_from_digest_chirho(
        &record_chirho.dag_chirho,
        &record_chirho.request_chirho,
        &record_chirho.scope_chirho,
        record_chirho.request_private_subject_chirho.as_deref(),
        record_chirho.caller_idempotency_key_digest_chirho.as_ref(),
        record_chirho.caller_operation_digest_chirho.as_ref(),
    )?;
    if record_chirho.idempotency_context_hash_chirho != expected_context_chirho {
        bail!("run intent record {idx_chirho} has mismatched idempotency context");
    }
    if record_chirho.run_chirho != run_intent_run_hash_chirho(&expected_context_chirho)? {
        bail!("run intent record {idx_chirho} has mismatched run id");
    }
    match &record_chirho.request_private_subject_chirho {
        Some(subject_chirho) => {
            // A verifier may not rest on an unverified line: the subject field of an appended
            // record is attacker-supplied until the record's own signature and blob ownership say
            // otherwise. Same verdict as the single-pair function, through the pass's resolver.
            if private_values_chirho
                .verified_record_chirho(subject_chirho, &record_chirho.request_chirho)?
                .is_none()
            {
                bail!(
                    "run intent record {idx_chirho} private request value {} missing",
                    record_chirho.request_chirho.0
                );
            }
        }
        None => {
            let _request_bytes_chirho =
                cas_chirho::get_chirho(root_chirho, &record_chirho.request_chirho).with_context(
                    || format!("run intent record {idx_chirho} request stone missing"),
                )?;
        }
    }
    let _dag_chirho: DagChirho =
        store_chirho::get_object_chirho(root_chirho, &record_chirho.dag_chirho)
            .with_context(|| format!("run intent record {idx_chirho} dag stone missing"))?;
    let message_chirho = run_intent_record_message_chirho(record_chirho)?;
    if !signer_chirho::verify_with_pubkey_chirho(
        pubkey_chirho,
        &message_chirho,
        &record_chirho.sig_chirho,
    )? {
        bail!("run intent record {idx_chirho} signature invalid");
    }
    Ok(())
}

pub(super) fn verify_run_intent_transition_chirho(
    record_chirho: &RunIntentRecordChirho,
    previous_chirho: Option<&str>,
) -> Result<()> {
    // An aborted run refused before any side effect: only a running run may abort, and its retry runs it again from
    // RUNNING (agy #25907).
    match (previous_chirho, record_chirho.status_chirho.as_str()) {
        (None, RUN_INTENT_PENDING_CHIRHO)
        | (Some(RUN_INTENT_PENDING_CHIRHO), RUN_INTENT_RUNNING_CHIRHO)
        | (Some(RUN_INTENT_ABORTED_CHIRHO), RUN_INTENT_RUNNING_CHIRHO)
        | (
            Some(RUN_INTENT_RUNNING_CHIRHO),
            RUN_INTENT_DONE_CHIRHO | RUN_INTENT_FAILED_CHIRHO | RUN_INTENT_ABORTED_CHIRHO,
        ) => Ok(()),
        _ => bail!(
            "run intent {} invalid transition to {}",
            record_chirho.run_chirho.0,
            record_chirho.status_chirho
        ),
    }
}

fn verify_error_fields_chirho(
    record_chirho: &RunIntentRecordChirho,
    idx_chirho: usize,
) -> Result<()> {
    // A failed run and an aborted one both record why (agy #25907); no other status carries an error.
    let carries_error_chirho = matches!(
        record_chirho.status_chirho.as_str(),
        RUN_INTENT_FAILED_CHIRHO | RUN_INTENT_ABORTED_CHIRHO
    );
    if carries_error_chirho != record_chirho.error_kind_chirho.is_some()
        || carries_error_chirho != record_chirho.error_digest_chirho.is_some()
    {
        bail!("run intent record {idx_chirho} has inconsistent error fields");
    }
    Ok(())
}
