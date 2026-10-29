// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have everlasting life. - John 3:16

//! Agent report and budget CLI helpers split out of dispatch_chirho.rs.

use crate::args_chirho::CommandChirho;
use cairn_chirho::agent_report_chirho;
use cairn_chirho::model_chirho::HashChirho;
use std::path::Path;

pub(crate) fn handle_agent_report_command_chirho(
    root_chirho: &Path,
    command_chirho: CommandChirho,
) -> anyhow::Result<Option<CommandChirho>> {
    match command_chirho {
        CommandChirho::AgentReportCreateChirho(args_chirho) => {
            let crate::args_chirho::agent_args_chirho::AgentReportCreateArgsChirho {
                producer_chirho,
                category_chirho,
                priority_chirho,
                happened_chirho,
                affected_chirho,
                why_matters_chirho,
                evidence_chirho,
                related_runs_chirho,
                related_effects_chirho,
                requested_action_chirho,
            } = args_chirho;
            let category_chirho =
                agent_report_chirho::parse_agent_report_category_chirho(&category_chirho)?;
            let priority_chirho =
                agent_report_chirho::parse_agent_report_priority_chirho(&priority_chirho)?;
            let evidence_refs_chirho = evidence_chirho
                .iter()
                .map(|raw_chirho| {
                    agent_report_chirho::parse_agent_report_evidence_ref_chirho(raw_chirho)
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            let requested_action_chirho = requested_action_chirho
                .as_deref()
                .map(agent_report_chirho::parse_agent_requested_action_chirho)
                .transpose()?;
            let record_chirho = agent_report_chirho::emit_agent_report_chirho(
                root_chirho,
                agent_report_chirho::AgentReportInputChirho {
                    producer_principal_chirho: producer_chirho,
                    category_chirho,
                    priority_chirho,
                    happened_chirho,
                    affected_chirho,
                    why_matters_chirho,
                    evidence_refs_chirho,
                    related_run_ids_chirho: related_runs_chirho
                        .into_iter()
                        .map(HashChirho)
                        .collect(),
                    related_effect_ids_chirho: related_effects_chirho,
                    requested_action_chirho,
                },
            )?;
            let mut charges_by_report_seq_chirho =
                agent_report_chirho::agent_report_charge_by_report_seq_chirho(root_chirho)?;
            let charge_chirho = charges_by_report_seq_chirho
                .remove(&record_chirho.seq_chirho)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "agent report #{} was written without a budget charge",
                        record_chirho.seq_chirho
                    )
                })?;
            println!(
                "agent report #{}\treport={}\tproducer={}\tcategory={}\tpriority={}\teffective-priority={}\tevidence={}\tcost-token={}\tremaining-token={}",
                record_chirho.seq_chirho,
                record_chirho.report_chirho.0,
                record_chirho.producer_principal_chirho,
                agent_report_chirho::category_label_chirho(&record_chirho.category_chirho),
                agent_report_chirho::priority_label_chirho(&record_chirho.priority_chirho),
                agent_report_chirho::priority_label_chirho(&charge_chirho.effective_priority_chirho),
                record_chirho.evidence_count_chirho,
                charge_chirho.cost_token_chirho,
                charge_chirho.remaining_budget_token_chirho
            );
            Ok(None)
        }
        CommandChirho::AgentReportShowChirho { report_chirho } => {
            let report_chirho = agent_report_chirho::load_agent_report_chirho(
                root_chirho,
                &HashChirho(report_chirho),
            )?;
            println!("{}", serde_json::to_string_pretty(&report_chirho)?);
            Ok(None)
        }
        CommandChirho::AgentReportsChirho(args_chirho) => {
            let crate::args_chirho::agent_args_chirho::AgentReportsArgsChirho {
                producer_chirho,
                category_chirho,
            } = args_chirho;
            let category_filter_chirho = category_chirho
                .as_deref()
                .map(agent_report_chirho::parse_agent_report_category_chirho)
                .transpose()?;
            let mut records_chirho =
                agent_report_chirho::load_agent_report_records_chirho(root_chirho)?;
            let charges_by_report_seq_chirho =
                agent_report_chirho::agent_report_charge_by_report_seq_chirho(root_chirho)?;
            records_chirho.sort_by_key(|record_chirho| record_chirho.seq_chirho);
            if records_chirho.is_empty() {
                println!("(no agent reports)");
            }
            for record_chirho in records_chirho {
                if let Some(producer_chirho) = &producer_chirho {
                    if producer_chirho != &record_chirho.producer_principal_chirho {
                        continue;
                    }
                }
                if let Some(category_chirho) = &category_filter_chirho {
                    if category_chirho != &record_chirho.category_chirho {
                        continue;
                    }
                }
                let effective_priority_chirho = charges_by_report_seq_chirho
                    .get(&record_chirho.seq_chirho)
                    .map(|charge_chirho| {
                        agent_report_chirho::priority_label_chirho(
                            &charge_chirho.effective_priority_chirho,
                        )
                    })
                    .unwrap_or("unreviewed-chirho");
                println!(
                    "#{}\treport={}\tproducer={}\tcategory={}\tpriority={}\teffective-priority={}\tevidence={}",
                    record_chirho.seq_chirho,
                    record_chirho.report_chirho.0,
                    record_chirho.producer_principal_chirho,
                    agent_report_chirho::category_label_chirho(&record_chirho.category_chirho),
                    agent_report_chirho::priority_label_chirho(&record_chirho.priority_chirho),
                    effective_priority_chirho,
                    record_chirho.evidence_count_chirho
                );
            }
            Ok(None)
        }
        CommandChirho::AgentReportVerifyChirho => {
            let count_chirho =
                agent_report_chirho::verify_agent_report_records_chirho(root_chirho)?;
            let charge_count_chirho =
                agent_report_chirho::verify_agent_report_accounting_chirho(root_chirho)?;
            println!(
                "verified {count_chirho} agent report record(s), {charge_count_chirho} charge record(s)"
            );
            Ok(None)
        }
        CommandChirho::AgentReportBudgetGrantChirho(args_chirho) => {
            let crate::args_chirho::agent_args_chirho::AgentReportBudgetGrantArgsChirho {
                agent_chirho,
                granted_by_chirho,
                amount_token_chirho,
                reason_chirho,
            } = args_chirho;
            let record_chirho = agent_report_chirho::grant_agent_report_budget_chirho(
                root_chirho,
                agent_report_chirho::AgentReportBudgetGrantInputChirho {
                    agent_principal_chirho: agent_chirho,
                    granted_by_chirho,
                    amount_token_chirho,
                    reason_chirho,
                },
            )?;
            println!(
                "agent report budget grant #{}\tagent={}\tamount-token={}\tgranted-by={}",
                record_chirho.seq_chirho,
                record_chirho.agent_principal_chirho,
                record_chirho.amount_token_chirho,
                record_chirho.granted_by_chirho
            );
            Ok(None)
        }
        CommandChirho::AgentReportBudgetChirho(args_chirho) => {
            let crate::args_chirho::agent_args_chirho::AgentReportBudgetArgsChirho { agent_chirho } =
                args_chirho;
            let balance_chirho = agent_report_chirho::agent_report_budget_balance_chirho(
                root_chirho,
                &agent_chirho,
            )?;
            println!(
                "agent={}\tgranted-token={}\tspent-token={}\tremaining-token={}",
                balance_chirho.agent_principal_chirho,
                balance_chirho.granted_token_chirho,
                balance_chirho.spent_token_chirho,
                balance_chirho.remaining_token_chirho
            );
            Ok(None)
        }
        CommandChirho::AgentReportChargesChirho(args_chirho) => {
            let crate::args_chirho::agent_args_chirho::AgentReportChargesArgsChirho {
                agent_chirho,
            } = args_chirho;
            let mut charges_chirho =
                agent_report_chirho::load_agent_report_charge_records_chirho(root_chirho)?;
            charges_chirho.sort_by_key(|charge_chirho| charge_chirho.seq_chirho);
            if charges_chirho.is_empty() {
                println!("(no agent report charges)");
            }
            for charge_chirho in charges_chirho {
                if let Some(agent_chirho) = &agent_chirho {
                    if agent_chirho != &charge_chirho.producer_principal_chirho {
                        continue;
                    }
                }
                println!(
                    "#{}\treport-seq={}\treport={}\tagent={}\trequested-priority={}\teffective-priority={}\tcost-token={}\tremaining-token={}\tdowngraded={}",
                    charge_chirho.seq_chirho,
                    charge_chirho.report_seq_chirho,
                    charge_chirho.report_chirho.0,
                    charge_chirho.producer_principal_chirho,
                    agent_report_chirho::priority_label_chirho(&charge_chirho.requested_priority_chirho),
                    agent_report_chirho::priority_label_chirho(&charge_chirho.effective_priority_chirho),
                    charge_chirho.cost_token_chirho,
                    charge_chirho.remaining_budget_token_chirho,
                    charge_chirho.priority_review_chirho.downgraded_chirho
                );
            }
            Ok(None)
        }
        other_chirho => Ok(Some(other_chirho)),
    }
}
