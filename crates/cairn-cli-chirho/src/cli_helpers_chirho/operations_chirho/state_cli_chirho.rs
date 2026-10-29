// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Branch, refs, reflog, causal reversion, and versioned-store CLI command handlers.

use crate::args_chirho::CommandChirho;
use cairn_chirho::model_chirho::HashChirho;
use cairn_chirho::{
    refs_chirho, reversion_legacy_evidence_chirho, store_chirho, store_seal_chirho, tenant_chirho,
    versioned_chirho, writer_head_chirho,
};
use cairn_dag_command_chirho::kv_path_chirho;
use std::path::Path;

pub(crate) fn handle_state_command_chirho(
    root_chirho: &Path,
    command_chirho: &CommandChirho,
) -> anyhow::Result<bool> {
    match command_chirho {
        CommandChirho::RollbackChirho(args_chirho) => {
            let crate::args_chirho::state_args_chirho::RollbackArgsChirho {
                branch_chirho,
                to_chirho,
            } = args_chirho;
            writer_head_chirho::with_head_commit_chirho(root_chirho, || {
                let current_chirho = refs_chirho::load_refs_chirho(root_chirho)?
                    .branches_chirho
                    .get(branch_chirho)
                    .cloned()
                    .ok_or_else(|| {
                        anyhow::anyhow!("no such branch '{branch_chirho}' to roll back")
                    })?;
                refs_chirho::commit_head_chirho(
                    root_chirho,
                    branch_chirho,
                    refs_chirho::HeadPreconditionChirho::ExpectedChirho(current_chirho),
                    HashChirho(to_chirho.clone()),
                    "rollback",
                )
            })?;
            println!("rolled '{branch_chirho}' back to {to_chirho}");
            Ok(true)
        }
        CommandChirho::BranchChirho(args_chirho) => {
            let crate::args_chirho::state_args_chirho::BranchArgsChirho {
                name_chirho,
                to_chirho,
            } = args_chirho;
            writer_head_chirho::with_head_commit_chirho(root_chirho, || {
                refs_chirho::commit_head_chirho(
                    root_chirho,
                    name_chirho,
                    refs_chirho::HeadPreconditionChirho::AnyCurrentChirho,
                    HashChirho(to_chirho.clone()),
                    "branch",
                )
            })?;
            println!("branch '{name_chirho}' -> {to_chirho}");
            Ok(true)
        }
        CommandChirho::RefsChirho => {
            let refs_val_chirho = refs_chirho::load_refs_chirho(root_chirho)?;
            println!("HEAD -> {}", refs_val_chirho.head_chirho);
            for (name_chirho, hash_chirho) in &refs_val_chirho.branches_chirho {
                println!("branch {name_chirho} {}", hash_chirho.0);
            }
            for (name_chirho, hash_chirho) in &refs_val_chirho.tags_chirho {
                println!("tag    {name_chirho} {}", hash_chirho.0);
            }
            Ok(true)
        }
        CommandChirho::ReflogChirho => {
            for entry_chirho in refs_chirho::reflog_chirho(root_chirho)? {
                let from_chirho = entry_chirho
                    .from_chirho
                    .map(|hash_chirho| hash_chirho.0)
                    .unwrap_or_else(|| "∅".to_string());
                println!(
                    "{} {:<8} {} -> {}  [{}]",
                    entry_chirho.at_ms_chirho,
                    entry_chirho.reason_chirho,
                    from_chirho,
                    entry_chirho.to_chirho.0,
                    entry_chirho.branch_chirho
                );
            }
            Ok(true)
        }
        CommandChirho::KvPutChirho(args_chirho) => {
            let crate::args_chirho::state_args_chirho::KvPutArgsChirho {
                key_chirho,
                value_chirho,
            } = args_chirho;
            let store_key_chirho =
                tenant_chirho::validated_store_key_for_root_chirho(root_chirho, key_chirho)?;
            let store_chirho =
                versioned_chirho::VersionedStoreChirho::open_chirho(&kv_path_chirho(root_chirho))?;
            // The operator door seals through the same helper as the blessed write arm; a
            // `kv-put` carries no app context, so the row rests under an `operator-store/` seal
            // subject. No production door writes a plaintext value into the versioned store.
            // The operator's own put: no request, no account owns or writes it.
            let sealed_chirho = store_seal_chirho::seal_and_put_store_value_chirho(
                root_chirho,
                &store_chirho,
                &cairn_chirho::privacy_chirho::PrivateBlobAttributionChirho::not_account_scoped_chirho(
                    cairn_chirho::privacy_chirho::NotAccountScopedReasonChirho::OperatorRunChirho,
                ),
                None,
                &store_key_chirho,
                value_chirho.as_bytes(),
            )?;
            println!("{key_chirho} -> v{}", sealed_chirho.version_chirho);
            Ok(true)
        }
        CommandChirho::KvGetChirho(args_chirho) => {
            let crate::args_chirho::state_args_chirho::KvGetArgsChirho {
                key_chirho,
                at_chirho,
            } = args_chirho;
            let store_key_chirho =
                tenant_chirho::validated_store_key_for_root_chirho(root_chirho, key_chirho)?;
            let store_chirho =
                versioned_chirho::VersionedStoreChirho::open_chirho(&kv_path_chirho(root_chirho))?;
            let bytes_chirho = match at_chirho {
                Some(version_chirho) => {
                    store_chirho.get_at_chirho(&store_key_chirho, *version_chirho)?
                }
                None => store_chirho.get_chirho(&store_key_chirho)?,
            };
            match bytes_chirho {
                Some(bytes_chirho) => println!("{}", String::from_utf8_lossy(&bytes_chirho)),
                None => println!("(absent)"),
            }
            Ok(true)
        }
        CommandChirho::KvVersionChirho => {
            let store_chirho =
                versioned_chirho::VersionedStoreChirho::open_chirho(&kv_path_chirho(root_chirho))?;
            println!("v{}", store_chirho.current_view_chirho()?);
            Ok(true)
        }
        CommandChirho::KvRollbackChirho { to_chirho } => {
            let store_chirho =
                versioned_chirho::VersionedStoreChirho::open_chirho(&kv_path_chirho(root_chirho))?;
            store_chirho.rollback_to_chirho(*to_chirho)?;
            println!("view -> v{to_chirho}");
            Ok(true)
        }
        _ => Ok(false),
    }
}

pub(crate) fn handle_reversion_command_chirho(
    root_chirho: &Path,
    command_chirho: &CommandChirho,
) -> anyhow::Result<bool> {
    match command_chirho {
        CommandChirho::ReversionEventsChirho => {
            let records_chirho =
                reversion_legacy_evidence_chirho::load_rollback_events_chirho(root_chirho)?;
            if records_chirho.is_empty() {
                println!("(no reversion events)");
            }
            for record_chirho in &records_chirho {
                let hash_chirho = store_chirho::hash_object_chirho(record_chirho)?;
                println!(
                    "#{}\tevent={}\tbranch={}\t{} -> {}\tactor={}\tgrant={}\tstates={}\teffects={}\tbudget_token={}",
                    record_chirho.seq_chirho,
                    hash_chirho.0,
                    record_chirho.branch_chirho,
                    record_chirho.from_chirho.0,
                    record_chirho.to_chirho.0,
                    record_chirho.actor_chirho,
                    record_chirho.grant_id_chirho,
                    record_chirho.consumed_states_chirho.len(),
                    record_chirho.dependent_effects_chirho.len(),
                    record_chirho.plan_cost_token_chirho
                );
            }
            Ok(true)
        }
        CommandChirho::ReversionCompensationsChirho => {
            let records_chirho =
                reversion_legacy_evidence_chirho::load_compensation_records_chirho(root_chirho)?;
            if records_chirho.is_empty() {
                println!("(no reversion compensations)");
            }
            for record_chirho in &records_chirho {
                println!(
                    "#{}\trollback={}\trun={}\teffect_seq={}\toriginal_effect={}\tidem={}\tstatus={:?}",
                    record_chirho.seq_chirho,
                    record_chirho.rollback_event_chirho.0,
                    record_chirho.original_run_chirho.0,
                    record_chirho.original_effect_seq_chirho,
                    record_chirho.original_effect_chirho.0,
                    record_chirho.idem_key_chirho.0,
                    record_chirho.status_chirho
                );
            }
            Ok(true)
        }
        CommandChirho::ReversionExecutionsChirho => {
            let records_chirho =
                reversion_legacy_evidence_chirho::load_compensation_executions_chirho(root_chirho)?;
            if records_chirho.is_empty() {
                println!("(no compensation execution records)");
            }
            for record_chirho in &records_chirho {
                println!(
                    "#{}\tcompensation={}\tidem={}\teffect={}\tcaller={}\tstatus={:?}",
                    record_chirho.seq_chirho,
                    record_chirho.compensation_seq_chirho,
                    record_chirho.compensation_idem_key_chirho.0,
                    record_chirho.effect_chirho,
                    record_chirho.caller_chirho,
                    record_chirho.status_chirho
                );
            }
            Ok(true)
        }
        CommandChirho::ReversionCompletionsChirho => {
            let records_chirho =
                reversion_legacy_evidence_chirho::load_rollback_completions_chirho(root_chirho)?;
            if records_chirho.is_empty() {
                println!("(no rollback completion records)");
            }
            for record_chirho in &records_chirho {
                println!(
                    "#{}\tevent={}\tresolved={:?}\tunresolved={:?}",
                    record_chirho.seq_chirho,
                    record_chirho.rollback_event_chirho.0,
                    record_chirho.resolved_compensations_chirho,
                    record_chirho.unresolved_compensations_chirho
                );
            }
            Ok(true)
        }
        CommandChirho::ReversionVerifyChirho => {
            let report_chirho =
                reversion_legacy_evidence_chirho::verify_reversion_evidence_chirho(root_chirho)?;
            println!(
                "reversion evidence verified: events={} compensations={} executions={} manual_resolutions={} completions={}",
                report_chirho.rollback_events_chirho,
                report_chirho.compensations_chirho,
                report_chirho.compensation_executions_chirho,
                report_chirho.manual_resolutions_chirho,
                report_chirho.rollback_completions_chirho
            );
            Ok(true)
        }
        CommandChirho::ReversionManualResolutionsChirho => {
            let records_chirho =
                reversion_legacy_evidence_chirho::load_manual_remediation_resolutions_chirho(
                    root_chirho,
                )?;
            if records_chirho.is_empty() {
                println!("(no manual remediation resolutions)");
            }
            for record_chirho in &records_chirho {
                println!(
                    "#{}\tcompensation={}\tidem={}\toperator={}\tnote={}",
                    record_chirho.seq_chirho,
                    record_chirho.compensation_seq_chirho,
                    record_chirho.compensation_idem_key_chirho.0,
                    record_chirho.operator_chirho,
                    record_chirho.note_chirho
                );
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}
