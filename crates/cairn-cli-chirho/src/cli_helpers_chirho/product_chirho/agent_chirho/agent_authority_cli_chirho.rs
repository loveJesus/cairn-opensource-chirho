// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have everlasting life. - John 3:16

//! Agent-authority CLI helpers split out of dispatch_chirho.rs.

use crate::args_chirho::CommandChirho;
use cairn_chirho::agent_authority_chirho;
use cairn_chirho::model_chirho::HashChirho;
use std::collections::BTreeMap;
use std::path::Path;

pub(crate) fn handle_agent_authority_command_chirho(
    root_chirho: &Path,
    command_chirho: CommandChirho,
) -> anyhow::Result<Option<CommandChirho>> {
    match command_chirho {
        CommandChirho::AgentAuthorityRespondChirho(args_chirho) => {
            let crate::args_chirho::agent_args_chirho::AgentAuthorityRespondArgsChirho {
                admin_chirho,
                agent_chirho,
                report_seq_chirho,
                report_chirho,
                kind_chirho,
                rule_chirho,
                scope_chirho,
                budget_token_chirho,
                param_chirho,
                reason_chirho,
            } = args_chirho;
            let kind_chirho =
                agent_authority_chirho::parse_agent_authority_change_kind_chirho(&kind_chirho)?;
            let mut parameter_changes_chirho = BTreeMap::new();
            for raw_param_chirho in param_chirho {
                let (key_chirho, value_chirho) =
                    agent_authority_chirho::parse_agent_authority_param_chirho(&raw_param_chirho)?;
                if parameter_changes_chirho
                    .insert(key_chirho.clone(), value_chirho)
                    .is_some()
                {
                    anyhow::bail!("duplicate authority param key {key_chirho}");
                }
            }
            let record_chirho = agent_authority_chirho::apply_agent_authority_response_chirho(
                root_chirho,
                agent_authority_chirho::AgentAuthorityResponseInputChirho {
                    admin_principal_chirho: admin_chirho,
                    agent_principal_chirho: agent_chirho,
                    report_seq_chirho,
                    report_chirho: HashChirho(report_chirho),
                    change_kind_chirho: kind_chirho,
                    rule_id_chirho: rule_chirho,
                    scope_chirho,
                    budget_token_chirho,
                    parameter_changes_chirho,
                    reason_chirho,
                },
            )?;
            println!(
                "agent authority #{}\tagent={}\trule={}\tkind={}\tstate={}",
                record_chirho.seq_chirho,
                record_chirho.agent_principal_chirho,
                record_chirho.rule_id_chirho,
                agent_authority_chirho::agent_authority_change_kind_label_chirho(
                    &record_chirho.change_kind_chirho
                ),
                record_chirho.new_state_chirho.0
            );
            Ok(None)
        }
        CommandChirho::AgentAuthorityShowChirho(args_chirho) => {
            let crate::args_chirho::agent_args_chirho::AgentAuthorityShowArgsChirho {
                agent_chirho,
            } = args_chirho;
            match agent_authority_chirho::current_agent_authority_state_chirho(
                root_chirho,
                &agent_chirho,
            )? {
                Some((hash_chirho, state_chirho)) => {
                    println!("state={}", hash_chirho.0);
                    println!("{}", serde_json::to_string_pretty(&state_chirho)?);
                }
                None => println!("(no agent authority ref for {agent_chirho})"),
            }
            Ok(None)
        }
        CommandChirho::AgentAuthorityCheckChirho(args_chirho) => {
            let crate::args_chirho::agent_args_chirho::AgentAuthorityCheckArgsChirho {
                agent_chirho,
                scope_chirho,
                cost_token_chirho,
            } = args_chirho;
            let decision_chirho = agent_authority_chirho::check_agent_action_authorized_chirho(
                root_chirho,
                &agent_chirho,
                &scope_chirho,
                cost_token_chirho,
            )?;
            println!("{}", serde_json::to_string_pretty(&decision_chirho)?);
            if !decision_chirho.authorized_chirho {
                anyhow::bail!("{}", decision_chirho.reason_chirho);
            }
            Ok(None)
        }
        CommandChirho::AgentAuthorityResponsesChirho(args_chirho) => {
            let crate::args_chirho::agent_args_chirho::AgentAuthorityResponsesArgsChirho {
                agent_chirho,
            } = args_chirho;
            let mut records_chirho =
                agent_authority_chirho::load_agent_authority_response_records_chirho(root_chirho)?;
            records_chirho.sort_by_key(|record_chirho| record_chirho.seq_chirho);
            if records_chirho.is_empty() {
                println!("(no agent authority responses)");
            }
            for record_chirho in records_chirho {
                if let Some(agent_chirho) = &agent_chirho {
                    if agent_chirho != &record_chirho.agent_principal_chirho {
                        continue;
                    }
                }
                println!(
                    "#{}\tagent={}\trule={}\tkind={}\treport=#{}\tstate={}",
                    record_chirho.seq_chirho,
                    record_chirho.agent_principal_chirho,
                    record_chirho.rule_id_chirho,
                    agent_authority_chirho::agent_authority_change_kind_label_chirho(
                        &record_chirho.change_kind_chirho
                    ),
                    record_chirho.report_seq_chirho,
                    record_chirho.new_state_chirho.0
                );
            }
            Ok(None)
        }
        CommandChirho::AgentAuthorityVerifyChirho => {
            let count_chirho =
                agent_authority_chirho::verify_agent_authority_responses_chirho(root_chirho)?;
            println!("verified {count_chirho} agent authority response record(s)");
            Ok(None)
        }
        other_chirho => Ok(Some(other_chirho)),
    }
}
