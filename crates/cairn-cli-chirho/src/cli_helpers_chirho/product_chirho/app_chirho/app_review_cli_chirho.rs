// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
//! App review CLI helpers split out of dispatch_chirho.rs.
use crate::args_chirho::CommandChirho;
use crate::parse_helpers_chirho::review_source_evidence_chirho;
use cairn_chirho::app_source_manifest_chirho;
use cairn_chirho::model_chirho::HashChirho;
use cairn_chirho::review_chirho;
use cairn_status_command_chirho::print_review_diff_chirho;
use std::path::Path;

pub(crate) fn handle_app_review_command_chirho(
    root_chirho: &Path,
    command_chirho: CommandChirho,
) -> anyhow::Result<Option<CommandChirho>> {
    match command_chirho {
        CommandChirho::ReviewDiffChirho(args_chirho) => {
            let crate::args_chirho::app_args_chirho::ReviewDiffArgsChirho {
                app_chirho,
                candidate_chirho,
                json_chirho,
            } = args_chirho;
            let diff_chirho = review_chirho::review_current_app_candidate_chirho(
                root_chirho,
                &app_chirho,
                HashChirho(candidate_chirho.clone()),
            )?;
            if json_chirho {
                println!("{}", serde_json::to_string_pretty(&diff_chirho)?);
            } else {
                print_review_diff_chirho(&diff_chirho);
            }
            Ok(None)
        }
        CommandChirho::ReviewPromoteChirho(args_chirho) => {
            let crate::args_chirho::app_args_chirho::ReviewPromoteArgsChirho {
                app_chirho,
                owner_chirho,
                candidate_chirho,
                source_review_report_chirho,
                source_manifest_chirho,
                raw_manifest_chirho,
                accept_capability_escalation_chirho,
                accept_cost_increase_chirho,
            } = args_chirho;
            let (source_review_report_chirho, source_manifest_chirho) =
                review_source_evidence_chirho(
                    source_review_report_chirho,
                    source_manifest_chirho,
                    raw_manifest_chirho,
                )?;
            let candidate_hash_chirho = HashChirho(candidate_chirho.clone());
            let source_review_for_install_chirho = match &source_review_report_chirho {
                Some(source_review_report_chirho) => Some(
                    app_source_manifest_chirho::load_app_source_review_report_for_promotion_chirho(
                        root_chirho,
                        &app_chirho,
                        &owner_chirho,
                        source_review_report_chirho,
                        Some(&candidate_hash_chirho),
                    )?,
                ),
                None => None,
            };
            if let (
                Some(source_review_report_hash_chirho),
                Some(source_review_for_install_chirho),
            ) = (
                &source_review_report_chirho,
                &source_review_for_install_chirho,
            ) {
                if let Some(install_report_chirho) =
                    app_source_manifest_chirho::reviewed_app_source_install_report_current_chirho(
                        root_chirho,
                        source_review_for_install_chirho,
                    )?
                {
                    if let Some(record_chirho) =
                        review_chirho::latest_promoted_source_review_record_chirho(
                            root_chirho,
                            &app_chirho,
                            &owner_chirho,
                            &candidate_hash_chirho,
                            source_review_report_hash_chirho,
                        )?
                    {
                        println!(
                            "review #{} already promoted app={} candidate={} source_review_report={} reviewed_routes={} reviewed_assets={}",
                            record_chirho.seq_chirho,
                            record_chirho.app_chirho,
                            record_chirho.candidate_chirho.0,
                            source_review_report_hash_chirho.0,
                            install_report_chirho.route_count_chirho,
                            install_report_chirho.asset_count_chirho
                        );
                        return Ok(None);
                    }
                }
            }
            // A failed promote or install puts the app's prior live surface back, and the error says whether
            // that worked.
            let (record_chirho, install_report_chirho) =
                app_source_manifest_chirho::promote_then_install_reviewed_source_chirho(
                    root_chirho,
                    &app_chirho,
                    &owner_chirho,
                    source_review_for_install_chirho.as_ref(),
                    || {
                        review_chirho::promote_candidate_with_review_evidence_chirho(
                            root_chirho,
                            review_chirho::PromoteCandidateReviewEvidenceInputChirho {
                                app_chirho: &app_chirho,
                                owner_principal_chirho: &owner_chirho,
                                candidate_chirho: candidate_hash_chirho,
                                accept_capability_escalation_chirho,
                                accept_cost_increase_chirho,
                                require_review_policy_envelope_chirho: false,
                                source_evidence_chirho: review_chirho::ReviewSourceEvidenceChirho {
                                    source_review_report_chirho,
                                    source_manifest_chirho,
                                },
                            },
                        )
                    },
                )?;
            let source_review_report_text_chirho = record_chirho
                .source_review_report_chirho
                .as_ref()
                .map(|hash_chirho| hash_chirho.0.as_str())
                .unwrap_or("(none)");
            let source_manifest_text_chirho = record_chirho
                .source_manifest_chirho
                .as_ref()
                .map(|source_chirho| source_chirho.effective_manifest_hash_chirho.0.as_str())
                .unwrap_or("(none)");
            let review_policy_envelope_text_chirho =
                review_policy_envelope_text_chirho(&record_chirho.review_policy_envelope_chirho);
            let route_count_chirho = install_report_chirho
                .as_ref()
                .map(|report_chirho| report_chirho.route_count_chirho.to_string())
                .unwrap_or_else(|| "(legacy)".to_string());
            let asset_count_chirho = install_report_chirho
                .as_ref()
                .map(|report_chirho| report_chirho.asset_count_chirho.to_string())
                .unwrap_or_else(|| "(legacy)".to_string());
            println!(
                "review #{} promoted app={} candidate={} source_review_report={} source_manifest={} review_policy_envelope={} app_record=#{} reviewed_routes={} reviewed_assets={} cost_delta={} accepted_caps={} accepted_cost={}",
                record_chirho.seq_chirho,
                record_chirho.app_chirho,
                record_chirho.candidate_chirho.0,
                source_review_report_text_chirho,
                source_manifest_text_chirho,
                review_policy_envelope_text_chirho,
                record_chirho
                    .app_record_seq_chirho
                    .map(|seq_chirho| seq_chirho.to_string())
                    .unwrap_or_else(|| "(none)".to_string()),
                route_count_chirho,
                asset_count_chirho,
                record_chirho.diff_chirho.cost_delta_token_chirho,
                record_chirho.accepted_capability_escalation_chirho,
                record_chirho.accepted_cost_increase_chirho
            );
            Ok(None)
        }
        CommandChirho::ReviewPolicyEnvelopeSetChirho(args_chirho) => {
            let crate::args_chirho::app_args_chirho::ReviewPolicyEnvelopeSetArgsChirho {
                app_chirho,
                owner_chirho,
                allowed_capability_labels_chirho,
                max_candidate_cost_token_chirho,
                allowed_contract_refs_chirho,
            } = args_chirho;
            let record_chirho = review_chirho::set_review_policy_envelope_chirho(
                root_chirho,
                &app_chirho,
                &owner_chirho,
                allowed_capability_labels_chirho,
                max_candidate_cost_token_chirho,
                allowed_contract_refs_chirho,
            )?;
            println!("review-policy envelope #{} app={} owner={} allowed_caps={} max_cost={} contract_refs={}", record_chirho.seq_chirho, record_chirho.app_chirho, owner_chirho, record_chirho.allowed_capability_labels_chirho.len(), record_chirho.max_candidate_cost_token_chirho, record_chirho.allowed_contract_refs_chirho.len());
            Ok(None)
        }
        CommandChirho::ReviewPolicyEnvelopeVerifyChirho => {
            let count_chirho = review_chirho::verify_review_policy_envelopes_chirho(root_chirho)?;
            println!("verified {count_chirho} review-policy envelope record(s)");
            Ok(None)
        }
        CommandChirho::ReviewRejectChirho(args_chirho) => {
            let crate::args_chirho::app_args_chirho::ReviewRejectArgsChirho {
                app_chirho,
                owner_chirho,
                candidate_chirho,
                source_review_report_chirho,
                source_manifest_chirho,
                raw_manifest_chirho,
                reason_chirho,
            } = args_chirho;
            let (source_review_report_chirho, source_manifest_chirho) =
                review_source_evidence_chirho(
                    source_review_report_chirho,
                    source_manifest_chirho,
                    raw_manifest_chirho,
                )?;
            let record_chirho = review_chirho::reject_candidate_with_review_evidence_chirho(
                root_chirho,
                &app_chirho,
                &owner_chirho,
                HashChirho(candidate_chirho.clone()),
                &reason_chirho,
                review_chirho::ReviewSourceEvidenceChirho {
                    source_review_report_chirho,
                    source_manifest_chirho,
                },
            )?;
            let source_review_report_text_chirho = record_chirho
                .source_review_report_chirho
                .as_ref()
                .map(|hash_chirho| hash_chirho.0.as_str())
                .unwrap_or("(none)");
            let source_manifest_text_chirho = record_chirho
                .source_manifest_chirho
                .as_ref()
                .map(|source_chirho| source_chirho.effective_manifest_hash_chirho.0.as_str())
                .unwrap_or("(none)");
            println!(
                "review #{} rejected app={} candidate={} source_review_report={} source_manifest={} cost_delta={} reason={}",
                record_chirho.seq_chirho,
                record_chirho.app_chirho,
                record_chirho.candidate_chirho.0,
                source_review_report_text_chirho,
                source_manifest_text_chirho,
                record_chirho.diff_chirho.cost_delta_token_chirho,
                record_chirho.reason_chirho.as_deref().unwrap_or("")
            );
            Ok(None)
        }
        CommandChirho::ReviewsChirho => {
            let records_chirho = review_chirho::load_review_records_chirho(root_chirho)?;
            if records_chirho.is_empty() {
                println!("(no review records)");
            }
            for record_chirho in &records_chirho {
                let source_review_report_chirho = record_chirho
                    .source_review_report_chirho
                    .as_ref()
                    .map(|hash_chirho| hash_chirho.0.as_str())
                    .unwrap_or("(none)");
                let source_manifest_chirho = record_chirho
                    .source_manifest_chirho
                    .as_ref()
                    .map(|source_chirho| source_chirho.effective_manifest_hash_chirho.0.as_str())
                    .unwrap_or("(none)");
                println!(
                    "#{}\t{:?}\tapp={}\tcandidate={}\tsource_review_report={}\tsource_manifest={}\tcost_delta={}\tadded_caps={}\tremoved_caps={}\treason={}",
                    record_chirho.seq_chirho,
                    record_chirho.decision_chirho,
                    record_chirho.app_chirho,
                    record_chirho.candidate_chirho.0,
                    source_review_report_chirho,
                    source_manifest_chirho,
                    record_chirho.diff_chirho.cost_delta_token_chirho,
                    record_chirho.diff_chirho.added_capabilities_chirho.len(),
                    record_chirho.diff_chirho.removed_capabilities_chirho.len(),
                    record_chirho.reason_chirho.as_deref().unwrap_or("")
                );
            }
            Ok(None)
        }
        CommandChirho::ReviewVerifyChirho => {
            let count_chirho = review_chirho::verify_review_records_chirho(root_chirho)?;
            println!("verified {count_chirho} review record(s)");
            Ok(None)
        }
        other_chirho => Ok(Some(other_chirho)),
    }
}
fn review_policy_envelope_text_chirho(
    evidence_chirho: &Option<review_chirho::ReviewPolicyEnvelopeEvidenceChirho>,
) -> String {
    match evidence_chirho {
        Some(review_chirho::ReviewPolicyEnvelopeEvidenceChirho::BoundChirho { envelope_seq_chirho, envelope_line_hash_chirho }) => format!("bound:seq={envelope_seq_chirho}:hash={}", envelope_line_hash_chirho.0),
        Some(review_chirho::ReviewPolicyEnvelopeEvidenceChirho::AbsentChirho { checked_envelope_count_chirho }) => format!("none:no review-policy envelope bound this promote:checked={checked_envelope_count_chirho}"),
        None => "legacy:not-recorded".to_string(),
    }
}
