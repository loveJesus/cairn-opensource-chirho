// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The startup resume of unfinished run intents: one verified fold of the log (the admission view's, checkpoint
//! brick S3), then each unfinished run resumed under its own lock from its latest record, re-verified fresh. An aborted
//! run is not unfinished: it refused before any side effect and waits for its own retry (agy #25907).

use super::*;

pub fn resume_unfinished_run_intents_chirho(
    root_chirho: &Path,
) -> Result<RunIntentResumeReportChirho> {
    resume_unfinished_run_intents_with_projection_read_chirho(root_chirho, None)
}

pub fn resume_unfinished_run_intents_with_projection_read_chirho(
    root_chirho: &Path,
    projection_read_chirho: Option<
        &dyn crate::effect_chirho::projection_read_chirho::PublishedProjectionReadPortChirho,
    >,
) -> Result<RunIntentResumeReportChirho> {
    resume_unfinished_run_intents_with_effect_runtime_chirho(
        root_chirho,
        crate::effect_chirho::DagEffectRuntimePortsChirho {
            projection_read_chirho,
            postgres_reversible_chirho: None,
            llm_served_chirho: None,
            private_attribution_chirho: None,
        },
    )
}

pub fn resume_unfinished_run_intents_with_effect_runtime_chirho(
    root_chirho: &Path,
    mut runtime_ports_chirho: crate::effect_chirho::DagEffectRuntimePortsChirho<'_>,
) -> Result<RunIntentResumeReportChirho> {
    // A declaration made at startup cannot know any one run's owner, so a resumed run's private values
    // take their attribution only from the context its scope rebuilds. A context-free run that stores
    // privately is therefore not resumed: it fails closed and its caller retries.
    runtime_ports_chirho.private_attribution_chirho = None;
    // Checkpoint brick S3: one verified fold of the log (the view's), where this was a whole-log verify and load plus
    // one more per unfinished run.
    let (record_count_chirho, unfinished_chirho) =
        seqlog_chirho::with_append_log_lock_chirho(root_chirho, || {
            admission_view_chirho::unfinished_runs_chirho(root_chirho)
        })?;
    let mut report_chirho = RunIntentResumeReportChirho {
        records_chirho: record_count_chirho,
        ..RunIntentResumeReportChirho::default()
    };
    for record_chirho in &unfinished_chirho {
        report_chirho.unfinished_chirho += 1;
        let admission_chirho = run_intent_admission_from_record_chirho(record_chirho);
        let lock_name_chirho = run_intent_execution_lock_name_chirho(&admission_chirho);
        let resume_result_chirho =
            seqlog_chirho::with_named_lock_chirho(root_chirho, &lock_name_chirho, || {
                let Some(latest_chirho) = latest_verified_run_intent_record_chirho(
                    root_chirho,
                    &record_chirho.run_chirho,
                )?
                else {
                    bail!("unfinished run intent disappeared from the verified log");
                };
                if !unfinished_status_chirho(&latest_chirho.status_chirho) {
                    return Ok(false);
                }
                resume_unfinished_run_intent_chirho(
                    root_chirho,
                    &latest_chirho,
                    runtime_ports_chirho.reborrow_chirho(),
                )?;
                Ok(true)
            });
        match resume_result_chirho {
            Ok(true) => report_chirho.resumed_chirho += 1,
            Ok(false) => {}
            Err(_error_chirho) => report_chirho.failed_chirho += 1,
        }
    }
    Ok(report_chirho)
}

fn resume_unfinished_run_intent_chirho(
    root_chirho: &Path,
    record_chirho: &RunIntentRecordChirho,
    runtime_ports_chirho: crate::effect_chirho::DagEffectRuntimePortsChirho<'_>,
) -> Result<()> {
    let admission_chirho = run_intent_admission_from_record_chirho(record_chirho);
    if record_chirho.status_chirho == RUN_INTENT_PENDING_CHIRHO {
        append_run_intent_record_chirho(
            root_chirho,
            &admission_chirho,
            RunIntentWriteStatusChirho::RunningChirho,
            None,
        )?;
    }
    let request_input_chirho = match &record_chirho.request_private_subject_chirho {
        Some(subject_chirho) => {
            match crate::dag_private_value_chirho::load_private_dag_value_bytes_chirho(
                root_chirho,
                subject_chirho,
                &record_chirho.request_chirho,
            ) {
                Ok(bytes_chirho) => dag_chirho::DagInputValueChirho::PrivateBytesChirho {
                    subject_chirho: subject_chirho.clone(),
                    bytes_chirho,
                },
                Err(error_chirho) => {
                    append_resume_failed_chirho(root_chirho, &admission_chirho, &error_chirho)?;
                    return Err(error_chirho);
                }
            }
        }
        None => match cas_chirho::get_chirho(root_chirho, &record_chirho.request_chirho) {
            Ok(request_chirho) => {
                dag_chirho::DagInputValueChirho::PublicBytesChirho(request_chirho)
            }
            Err(error_chirho) => {
                let error_chirho = anyhow!(error_chirho);
                append_resume_failed_chirho(root_chirho, &admission_chirho, &error_chirho)?;
                return Err(error_chirho);
            }
        },
    };
    let dag_chirho = match store_chirho::get_object_chirho(root_chirho, &record_chirho.dag_chirho) {
        Ok(dag_chirho) => dag_chirho,
        Err(error_chirho) => {
            append_resume_failed_chirho(root_chirho, &admission_chirho, &error_chirho)?;
            return Err(error_chirho);
        }
    };
    let context_chirho =
        match resume_request_context_chirho(root_chirho, &record_chirho.scope_chirho) {
            Ok(context_chirho) => context_chirho,
            Err(error_chirho) => {
                append_resume_failed_chirho(root_chirho, &admission_chirho, &error_chirho)?;
                return Err(error_chirho);
            }
        };
    let context_ref_chirho = context_chirho.as_ref();
    run_admitted_dag_chirho(
        root_chirho,
        &dag_chirho,
        request_input_chirho,
        context_ref_chirho,
        &admission_chirho,
        RunIntentExecutionModeChirho::ResumeChirho,
        runtime_ports_chirho,
    )
    .map(|_report_chirho| ())
}

/// A run's latest record for a resume, from the verified view under the append-log lock, re-verified fresh (checkpoint
/// brick S3, option (a)): O(delta) plus one record, where it was a whole-log verify per unfinished run.
fn latest_verified_run_intent_record_chirho(
    root_chirho: &Path,
    run_chirho: &HashChirho,
) -> Result<Option<RunIntentRecordChirho>> {
    seqlog_chirho::with_append_log_lock_chirho(root_chirho, || {
        let latest_chirho =
            admission_view_chirho::latest_record_for_run_chirho(root_chirho, run_chirho)?;
        if let Some(latest_chirho) = &latest_chirho {
            admission_view_chirho::reverify_fresh_chirho(root_chirho, latest_chirho)?;
        }
        Ok(latest_chirho)
    })
}

fn append_resume_failed_chirho(
    root_chirho: &Path,
    admission_chirho: &RunIntentAdmissionChirho,
    error_chirho: &anyhow::Error,
) -> Result<()> {
    let digest_chirho = cas_chirho::hash_chirho(error_chirho.to_string().as_bytes());
    append_run_intent_record_chirho(
        root_chirho,
        admission_chirho,
        RunIntentWriteStatusChirho::FailedChirho,
        Some(("run-intent-resume-failed-chirho", digest_chirho)),
    )
    .map(|_record_chirho| ())
}

pub fn resume_request_context_chirho(
    root_chirho: &Path,
    scope_chirho: &RunIntentScopeChirho,
) -> Result<Option<RequestContextChirho>> {
    if scope_chirho.kind_chirho == "public-run-chirho" {
        let expected_chirho = run_intent_scope_chirho(root_chirho, None)?;
        if &expected_chirho != scope_chirho {
            bail!("public run-intent scope carries app-only fields");
        }
        return Ok(None);
    }
    if scope_chirho.kind_chirho != "app-run-chirho" {
        bail!(
            "run-intent scope kind '{}' cannot be resumed",
            scope_chirho.kind_chirho
        );
    }
    let token_hash_chirho = scope_chirho
        .token_hash_chirho
        .as_ref()
        .ok_or_else(|| anyhow!("app run-intent scope missing token hash"))?;
    // K4: a connection key is always a limited key, so its run is not resumed (the rule below). Its row lives in the
    // connection token log, which the legacy lookup here never reads, so it is refused by that rule here rather than
    // as a key with no row.
    if oauth_chirho::connection_token_hash_recorded_chirho(root_chirho, token_hash_chirho)? {
        bail!("a limited key's run is not resumed");
    }
    oauth_chirho::verify_scoped_tokens_chirho(root_chirho)?;
    let token_chirho = oauth_chirho::load_scoped_tokens_chirho(root_chirho)?
        .into_iter()
        .rev()
        .find(|token_chirho| token_chirho.token_hash_chirho == *token_hash_chirho)
        .ok_or_else(|| anyhow!("run-intent scoped token hash has no verified token row"))?;
    // A limited key's request carried a limit its token row alone cannot rebuild exactly, and a context rebuilt without
    // it would be wider than the key's grant. So its run is not resumed: the caller re-reads, as for any unknown outcome.
    if cairn_capability_chirho::capability_key_grant_chirho::scopes_mark_limited_key_chirho(
        &token_chirho.scopes_chirho,
    ) {
        bail!("a limited key's run is not resumed");
    }
    let owner_principal_chirho =
        app_chirho::verified_app_owner_chirho(root_chirho, &token_chirho.app_chirho)?
            .ok_or_else(|| anyhow!("run-intent app has no verified owner"))?;
    let context_chirho = RequestContextChirho {
        user_principal_chirho: token_chirho.principal_chirho,
        app_chirho: token_chirho.app_chirho,
        owner_principal_chirho,
        client_id_chirho: token_chirho.client_id_chirho,
        token_hash_chirho: token_chirho.token_hash_chirho,
        price_book_chirho: scope_chirho.price_book_chirho.clone(),
        billing_policy_chirho: scope_chirho.billing_policy_chirho.clone(),
        key_limit_chirho: None,
    };
    let expected_scope_chirho = run_intent_scope_chirho(root_chirho, Some(&context_chirho))?;
    if &expected_scope_chirho != scope_chirho {
        bail!("verified app context does not match run-intent scope indexes");
    }
    Ok(Some(context_chirho))
}
