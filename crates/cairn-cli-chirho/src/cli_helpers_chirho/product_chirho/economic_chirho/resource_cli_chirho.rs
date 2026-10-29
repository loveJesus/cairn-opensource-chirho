// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Resource policy, usage, rollup, and status CLI helpers split out of economic_cli_chirho.rs.

use crate::args_chirho::CommandChirho;
use crate::parse_helpers_chirho::parse_resource_bridges_chirho;
use cairn_chirho::model_chirho::HashChirho;
use cairn_chirho::resource_chirho;
use std::path::Path;

pub(super) fn handle_resource_command_chirho(
    root_chirho: &Path,
    command_chirho: CommandChirho,
) -> anyhow::Result<Option<CommandChirho>> {
    match command_chirho {
        CommandChirho::ResourcePolicySetChirho(args_chirho) => {
            let crate::args_chirho::economic_args_chirho::ResourcePolicySetArgsChirho {
                app_chirho,
                owner_chirho,
                file_chirho,
            } = args_chirho;
            let text_chirho = std::fs::read_to_string(&file_chirho)?;
            let input_chirho: resource_chirho::ResourcePolicyInputChirho =
                serde_json::from_str(&text_chirho)?;
            let (hash_chirho, policy_chirho, record_chirho) =
                resource_chirho::set_resource_policy_from_input_chirho(
                    root_chirho,
                    &app_chirho,
                    &owner_chirho,
                    input_chirho,
                )?;
            println!(
                "resource policy for '{app_chirho}' -> {} owner={} record #{}",
                hash_chirho.0, owner_chirho, record_chirho.seq_chirho
            );
            println!(
                "  meters={} actions={}",
                policy_chirho.meters_chirho.len(),
                policy_chirho.actions_chirho.len()
            );
            if let Some(previous_chirho) = policy_chirho.previous_chirho {
                println!("  previous: {}", previous_chirho.0);
            }
            println!("  rollback: rollback resource-policy/{app_chirho} <hash>");
            Ok(None)
        }
        CommandChirho::ResourcePolicyUnsetChirho(args_chirho) => {
            let crate::args_chirho::economic_args_chirho::ResourcePolicyUnsetArgsChirho {
                app_chirho,
                owner_chirho,
            } = args_chirho;
            match resource_chirho::unset_resource_policy_chirho(
                root_chirho,
                &app_chirho,
                &owner_chirho,
            )? {
                Some(record_chirho) => {
                    println!(
                        "removed resource policy for '{app_chirho}' owner={} previous={} unset record #{}",
                        owner_chirho, record_chirho.previous_chirho.0, record_chirho.seq_chirho
                    );
                }
                None => println!("(no resource policy for app '{app_chirho}' to remove)"),
            }
            Ok(None)
        }
        CommandChirho::ResourcePolicyShowChirho { app_chirho } => {
            match resource_chirho::current_resource_policy_chirho(root_chirho, &app_chirho)? {
                Some((hash_chirho, policy_chirho)) => {
                    println!("resource policy for '{app_chirho}' -> {}", hash_chirho.0);
                    println!("{}", serde_json::to_string_pretty(&policy_chirho)?);
                    println!("rollback: rollback resource-policy/{app_chirho} <hash>");
                }
                None => println!("(no resource policy for app '{app_chirho}')"),
            }
            Ok(None)
        }
        CommandChirho::ResourcePolicyHistoryChirho { app_chirho } => {
            let current_chirho =
                resource_chirho::current_resource_policy_hash_chirho(root_chirho, &app_chirho)?;
            let records_chirho =
                resource_chirho::resource_policy_history_chirho(root_chirho, &app_chirho)?;
            if records_chirho.is_empty() {
                println!("(no resource policies for app '{app_chirho}')");
            }
            for record_chirho in &records_chirho {
                let current_marker_chirho =
                    if Some(&record_chirho.resource_policy_chirho) == current_chirho.as_ref() {
                        " current"
                    } else {
                        ""
                    };
                let previous_chirho = record_chirho
                    .previous_chirho
                    .as_ref()
                    .map(|hash_chirho| hash_chirho.0.as_str())
                    .unwrap_or("(none)");
                println!(
                    "#{}\t{}{}\towner={}\tprevious={}\tat_ms={}",
                    record_chirho.seq_chirho,
                    record_chirho.resource_policy_chirho.0,
                    current_marker_chirho,
                    record_chirho.owner_principal_chirho,
                    previous_chirho,
                    record_chirho.at_ms_chirho
                );
            }
            println!("rollback: rollback resource-policy/{app_chirho} <hash>");
            Ok(None)
        }
        CommandChirho::ResourcePolicyVerifyChirho => {
            let policies_chirho = resource_chirho::verify_resource_policies_chirho(root_chirho)?;
            let unsets_chirho = resource_chirho::verify_resource_policy_unsets_chirho(root_chirho)?;
            let usage_chirho = resource_chirho::verify_resource_usage_chirho(root_chirho)?;
            println!(
                "verified {policies_chirho} resource policy record(s), {unsets_chirho} resource policy unset record(s), {usage_chirho} resource usage record(s)"
            );
            Ok(None)
        }
        CommandChirho::ResourceUseChirho(args_chirho) => {
            let crate::args_chirho::economic_args_chirho::ResourceUseArgsChirho {
                app_chirho,
                user_chirho,
                actor_chirho,
                section_chirho,
                action_chirho,
                effect_chirho,
                run_chirho,
                bridges_chirho,
            } = args_chirho;
            let bridges_chirho = parse_resource_bridges_chirho(&bridges_chirho)?;
            let record_chirho = resource_chirho::record_resource_usage_chirho(
                root_chirho,
                resource_chirho::ResourceUsageInputChirho {
                    app_chirho,
                    user_chirho,
                    actor_chirho,
                    section_chirho,
                    action_chirho,
                    effect_chirho,
                    run_chirho: run_chirho.map(HashChirho),
                    bridges_chirho,
                },
            )?;
            println!(
                "resource usage #{}\tapp={}\tuser={}\tactor={}\tsection={}\taction={}\tbridges={}\tdecision={:?}",
                record_chirho.seq_chirho,
                record_chirho.app_chirho,
                record_chirho.user_chirho,
                record_chirho.actor_chirho,
                record_chirho.section_chirho,
                record_chirho.action_chirho,
                record_chirho.bridges_chirho.len(),
                record_chirho.decision_chirho
            );
            Ok(None)
        }
        CommandChirho::ResourceUsageChirho(args_chirho) => {
            let crate::args_chirho::economic_args_chirho::ResourceUsageArgsChirho { app_chirho } =
                args_chirho;
            resource_chirho::verify_resource_usage_chirho(root_chirho)?;
            let records_chirho = resource_chirho::load_resource_usage_chirho(root_chirho)?;
            let mut printed_chirho = 0_usize;
            for record_chirho in &records_chirho {
                if app_chirho
                    .as_deref()
                    .is_some_and(|app_chirho| app_chirho != record_chirho.app_chirho)
                {
                    continue;
                }
                printed_chirho += 1;
                println!(
                    "#{}\tapp={}\tuser={}\tactor={}\tsection={}\taction={}\tcharges={}\tbridges={}\tdecision={:?}",
                    record_chirho.seq_chirho,
                    record_chirho.app_chirho,
                    record_chirho.user_chirho,
                    record_chirho.actor_chirho,
                    record_chirho.section_chirho,
                    record_chirho.action_chirho,
                    record_chirho
                        .charges_chirho
                        .iter()
                        .map(|charge_chirho| format!(
                            "{}:{}",
                            charge_chirho.resource_chirho, charge_chirho.amount_chirho
                        ))
                        .collect::<Vec<_>>()
                        .join(","),
                    record_chirho.bridges_chirho.len(),
                    record_chirho.decision_chirho
                );
            }
            if printed_chirho == 0 {
                println!("(no resource usage)");
            }
            Ok(None)
        }
        CommandChirho::ResourceRollupChirho(args_chirho) => {
            let crate::args_chirho::economic_args_chirho::ResourceRollupArgsChirho {
                axis_chirho,
                app_chirho,
            } = args_chirho;
            let axis_chirho =
                resource_chirho::ResourceRollupAxisChirho::parse_chirho(&axis_chirho)?;
            let rows_chirho = resource_chirho::resource_rollup_chirho(
                root_chirho,
                app_chirho.as_deref(),
                axis_chirho,
            )?;
            if rows_chirho.is_empty() {
                println!("(no resource usage)");
            }
            for row_chirho in &rows_chirho {
                println!(
                    "{}\tresource={}\tunit={}\tusage={}\tamount={}",
                    row_chirho.key_chirho,
                    row_chirho.resource_chirho,
                    row_chirho.unit_chirho,
                    row_chirho.usage_count_chirho,
                    row_chirho.amount_chirho
                );
            }
            Ok(None)
        }
        CommandChirho::ResourceStatusChirho(args_chirho) => {
            let crate::args_chirho::economic_args_chirho::ResourceStatusArgsChirho {
                app_chirho,
                user_chirho,
            } = args_chirho;
            let rows_chirho = resource_chirho::resource_status_chirho(
                root_chirho,
                app_chirho.as_deref(),
                user_chirho.as_deref(),
            )?;
            if rows_chirho.is_empty() {
                println!("(no resource status)");
            }
            for row_chirho in &rows_chirho {
                println!(
                    "app={}\tscope={:?}\tsubject={}\tresource={}\tunit={}\tstack={}\tlimit={}\twindow_ms={}\tused={}\tremaining={}\trouted_attempts={}\trouted_amount={}\troute={}",
                    row_chirho.app_chirho,
                    row_chirho.scope_chirho,
                    row_chirho.subject_chirho,
                    row_chirho.resource_chirho,
                    row_chirho.unit_chirho,
                    row_chirho.stack_chirho.as_deref().unwrap_or("(none)"),
                    row_chirho.limit_chirho,
                    row_chirho
                        .window_ms_chirho
                        .map(|value_chirho| value_chirho.to_string())
                        .unwrap_or_else(|| "(cumulative)".to_string()),
                    row_chirho.used_chirho,
                    row_chirho.remaining_chirho,
                    row_chirho.routed_attempts_chirho,
                    row_chirho.routed_amount_chirho,
                    row_chirho.route_chirho.as_deref().unwrap_or("(none)")
                );
            }
            Ok(None)
        }
        other_chirho => Ok(Some(other_chirho)),
    }
}
