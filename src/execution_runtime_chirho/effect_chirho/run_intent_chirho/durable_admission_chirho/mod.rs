// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! A fenced durable admission, deliberately separate from executing the admitted DAG.
//! Workflow: spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/run-admission-chirho/workflow-chirho.md.

use super::*;
use cairn_writer_head_chirho::run_admission_authority_chirho::{
    RunAdmissionAuthorityPortChirho, RunAdmissionCommitActionChirho, RunAdmissionCommitScopeChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    writer_authority_era_chirho, WriterAuthorityEraChirho,
};

/// Request semantics only. Neither the caller key nor these fields grant writer authority.
pub struct PrivateRunAdmissionRequestChirho<'request_chirho> {
    pub dag_chirho: &'request_chirho HashChirho,
    pub subject_chirho: &'request_chirho str,
    pub bytes_chirho: &'request_chirho [u8],
    pub context_chirho: Option<&'request_chirho RequestContextChirho>,
    /// Whose container the private request joins when there is no request context. With a context, the
    /// context decides and this is unused; with neither, the private store refuses.
    pub declared_attribution_chirho:
        Option<&'request_chirho crate::privacy_chirho::PrivateBlobAttributionChirho>,
    pub caller_key_chirho: &'request_chirho CallerIdempotencyKeyChirho,
    pub operation_chirho: Option<&'request_chirho CallerOperationBindingChirho>,
}

/// Commit the private request before exactly one PENDING record, or return its verified replay.
/// No DAG executes here. No cache, result, effect, token use, metering, or application state is written.
/// Existing execution entry points are not yet threaded through this port and remain unconverted.
pub fn admit_private_run_intent_chirho(
    root_chirho: &Path,
    authority_chirho: &dyn RunAdmissionAuthorityPortChirho,
    request_chirho: PrivateRunAdmissionRequestChirho<'_>,
) -> Result<RunIntentRecordChirho> {
    crate::privacy_chirho::validate_privacy_subject_chirho(request_chirho.subject_chirho)?;
    if writer_authority_era_chirho(root_chirho)? != WriterAuthorityEraChirho::ElectedChirho {
        bail!("RunAdmissionElectedEraRequiredChirho");
    }
    let caller_digest_chirho =
        caller_idempotency_key_digest_chirho(request_chirho.caller_key_chirho);
    let lock_name_chirho = format!("run-intent-caller-key-v1-chirho:{}", caller_digest_chirho.0);
    seqlog_chirho::with_named_lock_chirho(root_chirho, &lock_name_chirho, || {
        struct AdmissionActionChirho<'request_chirho> {
            root_chirho: &'request_chirho Path,
            request_chirho: PrivateRunAdmissionRequestChirho<'request_chirho>,
            result_chirho: Option<Result<RunIntentRecordChirho>>,
            calls_chirho: usize,
        }
        impl RunAdmissionCommitActionChirho for AdmissionActionChirho<'_> {
            fn call_chirho(
                &mut self,
                scope_chirho: RunAdmissionCommitScopeChirho<'_>,
            ) -> Result<()> {
                self.calls_chirho += 1;
                if self.calls_chirho != 1 {
                    bail!("RunAdmissionCallbackRepeatedChirho");
                }
                self.result_chirho = Some(commit_private_admission_chirho(
                    self.root_chirho,
                    &scope_chirho,
                    &self.request_chirho,
                ));
                Ok(())
            }
        }
        let mut action_chirho = AdmissionActionChirho {
            root_chirho,
            request_chirho,
            result_chirho: None,
            calls_chirho: 0,
        };
        authority_chirho
            .with_elected_run_admission_scope_chirho(root_chirho, &mut action_chirho)?;
        if action_chirho.calls_chirho != 1 {
            bail!("RunAdmissionCallbackMissingChirho");
        }
        action_chirho.result_chirho.take().unwrap()
    })
}

fn commit_private_admission_chirho(
    root_chirho: &Path,
    scope_chirho: &RunAdmissionCommitScopeChirho<'_>,
    request_chirho: &PrivateRunAdmissionRequestChirho<'_>,
) -> Result<RunIntentRecordChirho> {
    scope_chirho.validate_sink_chirho(root_chirho)?;
    let _dag_chirho: DagChirho =
        store_chirho::get_object_chirho(root_chirho, request_chirho.dag_chirho)?;
    // Scope hashing may initialize the instance index key, so it belongs inside held authority too.
    let request_hash_chirho = cas_chirho::hash_chirho(request_chirho.bytes_chirho);
    let run_scope_chirho = run_intent_scope_chirho(root_chirho, request_chirho.context_chirho)?;
    let caller_digest_chirho =
        caller_idempotency_key_digest_chirho(request_chirho.caller_key_chirho);
    let operation_digest_chirho = request_chirho
        .operation_chirho
        .map(caller_operation_digest_chirho);
    let context_hash_chirho = run_intent_context_hash_from_digest_chirho(
        request_chirho.dag_chirho,
        &request_hash_chirho,
        &run_scope_chirho,
        Some(request_chirho.subject_chirho),
        Some(&caller_digest_chirho),
        operation_digest_chirho.as_ref(),
    )?;
    let admission_chirho = RunIntentAdmissionChirho {
        run_chirho: run_intent_run_hash_chirho(&context_hash_chirho)?,
        dag_chirho: request_chirho.dag_chirho.clone(),
        request_chirho: request_hash_chirho,
        request_private_subject_chirho: Some(request_chirho.subject_chirho.to_string()),
        caller_idempotency_key_digest_chirho: Some(caller_digest_chirho),
        caller_operation_digest_chirho: operation_digest_chirho,
        idempotency_context_hash_chirho: context_hash_chirho,
        scope_chirho: run_scope_chirho,
    };
    if let Some(record_chirho) =
        latest_verified_run_intent_record_for_admission_chirho(root_chirho, &admission_chirho)?
    {
        if !run_intent_admission_matches_chirho(
            &run_intent_admission_from_record_chirho(&record_chirho),
            &admission_chirho,
        ) {
            bail!("RunAdmissionEvidenceCollisionChirho");
        }
        return Ok(record_chirho);
    }
    #[cfg(test)]
    tests_chirho::hold_before_sink_chirho(root_chirho, tests_chirho::SinkPointChirho::StoreChirho)?;
    scope_chirho.validate_sink_chirho(root_chirho)?;
    persist_request_before_admission_chirho(
        root_chirho,
        &dag_chirho::DagInputValueChirho::PrivateBytesChirho {
            subject_chirho: request_chirho.subject_chirho.to_string(),
            bytes_chirho: request_chirho.bytes_chirho.to_vec(),
        },
        &admission_chirho,
        // A private admission is the signed-in request user's own input: its context attributes it.
        // Without a context, its caller's declaration does, or the store refuses.
        &crate::dag_private_value_chirho::RunAttributionSourceChirho::new_chirho(
            request_chirho.context_chirho,
            request_chirho.declared_attribution_chirho,
        ),
    )?;
    #[cfg(test)]
    tests_chirho::hold_before_sink_chirho(
        root_chirho,
        tests_chirho::SinkPointChirho::AppendChirho,
    )?;
    scope_chirho.validate_sink_chirho(root_chirho)?;
    append_run_intent_record_chirho(
        root_chirho,
        &admission_chirho,
        RunIntentWriteStatusChirho::PendingChirho,
        None,
    )
}

#[cfg(test)]
mod tests_chirho;
