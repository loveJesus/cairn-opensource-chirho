// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Billing policy, rollup, refund, and compensation CLI helpers split out of economic_cli_chirho.rs.

use crate::args_chirho::CommandChirho;
use cairn_chirho::economic_model_chirho::BillingRollupAxisChirho;
use cairn_chirho::legacy_billing_evidence_chirho;
use cairn_chirho::legacy_evidence_readers_chirho;
use cairn_status_command_chirho::print_spend_caps_chirho;
use std::path::Path;

pub(super) fn handle_billing_command_chirho(
    root_chirho: &Path,
    command_chirho: CommandChirho,
) -> anyhow::Result<Option<CommandChirho>> {
    match command_chirho {
        CommandChirho::BillingPolicyShowChirho { app_chirho } => {
            match legacy_billing_evidence_chirho::current_billing_policy_single_road_chirho(
                root_chirho,
                &app_chirho,
            )? {
                Some((hash_chirho, policy_chirho)) => {
                    println!("billing policy for '{app_chirho}' -> {}", hash_chirho.0);
                    println!("  owner: {}", policy_chirho.owner_principal_chirho);
                    println!("  default: {}", policy_chirho.default_chirho.label_chirho());
                    print_spend_caps_chirho(&policy_chirho.spend_caps_chirho);
                    if policy_chirho.effect_overrides_chirho.is_empty() {
                        println!("  effect overrides: (none)");
                    } else {
                        for (effect_chirho, mode_chirho) in &policy_chirho.effect_overrides_chirho {
                            println!("  {effect_chirho}: {}", mode_chirho.label_chirho());
                        }
                    }
                    if let Some(previous_chirho) = policy_chirho.previous_chirho {
                        println!("  previous: {}", previous_chirho.0);
                    }
                    println!("  rollback: rollback billing/{app_chirho} <hash>");
                }
                None => println!("billing policy for '{app_chirho}': user-pays (implicit)"),
            }
            Ok(None)
        }
        CommandChirho::BillingPolicyHistoryChirho { app_chirho } => {
            let current_chirho =
                legacy_billing_evidence_chirho::current_billing_policy_hash_single_road_chirho(
                    root_chirho,
                    &app_chirho,
                )?;
            let records_chirho = legacy_billing_evidence_chirho::billing_policy_history_chirho(
                root_chirho,
                &app_chirho,
            )?;
            if records_chirho.is_empty() {
                println!("(no explicit billing policies for app '{app_chirho}')");
            }
            for record_chirho in &records_chirho {
                let current_marker_chirho =
                    if Some(&record_chirho.billing_policy_chirho) == current_chirho.as_ref() {
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
                    record_chirho.billing_policy_chirho.0,
                    current_marker_chirho,
                    record_chirho.owner_principal_chirho,
                    previous_chirho,
                    record_chirho.at_ms_chirho
                );
            }
            println!("rollback: rollback billing/{app_chirho} <hash>");
            Ok(None)
        }
        CommandChirho::BillingPolicyVerifyChirho => {
            let policies_chirho =
                legacy_billing_evidence_chirho::verify_billing_policies_single_road_chirho(
                    root_chirho,
                )?;
            let usage_chirho =
                legacy_billing_evidence_chirho::verify_billing_usage_single_road_chirho(
                    root_chirho,
                )?;
            let compensations_chirho =
                legacy_billing_evidence_chirho::verify_billing_compensations_single_road_chirho(
                    root_chirho,
                )?;
            println!(
                "verified {policies_chirho} billing policy record(s), {usage_chirho} usage record(s), {compensations_chirho} compensation record(s)"
            );
            Ok(None)
        }
        CommandChirho::BillingRollupChirho(args_chirho) => {
            let crate::args_chirho::economic_args_chirho::BillingRollupArgsChirho { axis_chirho } =
                args_chirho;
            let axis_val_chirho = BillingRollupAxisChirho::parse_chirho(&axis_chirho)?;
            let rows_chirho = legacy_billing_evidence_chirho::billing_rollup_chirho(
                root_chirho,
                axis_val_chirho,
            )?;
            if rows_chirho.is_empty() {
                println!("(no billing usage)");
            }
            for row_chirho in &rows_chirho {
                println!(
                    "{}\tusage={}\tamount={}",
                    row_chirho.key_chirho, row_chirho.usage_count_chirho, row_chirho.amount_chirho
                );
            }
            Ok(None)
        }
        CommandChirho::BillingCompensationsChirho => {
            let records_chirho =
                legacy_evidence_readers_chirho::load_billing_compensations_chirho(root_chirho)?;
            if records_chirho.is_empty() {
                println!("(no billing compensations)");
            }
            for record_chirho in records_chirho {
                println!(
                    "#{}\tusage=#{}\tledger=#{}\tapp={}\tcaller={}\tpayer={}\tamount={}\treason={}",
                    record_chirho.seq_chirho,
                    record_chirho.original_usage_seq_chirho,
                    record_chirho.ledger_seq_chirho,
                    record_chirho.app_chirho,
                    record_chirho.caller_chirho,
                    record_chirho.payer_chirho,
                    record_chirho.amount_token_chirho,
                    record_chirho.reason_chirho
                );
            }
            Ok(None)
        }
        other_chirho => Ok(Some(other_chirho)),
    }
}
