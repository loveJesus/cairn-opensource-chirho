// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have everlasting life. - John 3:16

//! Privacy, legal hold, replica, backup-policy, and erasure-propagation CLI helpers split out of dispatch_chirho.rs.

use crate::args_chirho::CommandChirho;
use cairn_chirho::{
    data_rights_chirho, legal_hold_chirho, privacy_backup_chirho, privacy_chirho, retention_chirho,
};
use std::path::Path;

pub(crate) fn handle_privacy_command_chirho(
    root_chirho: &Path,
    command_chirho: CommandChirho,
) -> anyhow::Result<Option<CommandChirho>> {
    match command_chirho {
        CommandChirho::PrivacyExportChirho(args_chirho) => {
            let crate::args_chirho::privacy_args_chirho::PrivacyExportArgsChirho {
                subject_chirho,
                requested_by_chirho,
                include_private_chirho,
            } = args_chirho;
            let export_chirho = data_rights_chirho::export_subject_portable_data_chirho(
                root_chirho,
                &subject_chirho,
                include_private_chirho,
            )?;
            let export_chirho =
                data_rights_chirho::finalize_subject_portable_data_export_with_evidence_chirho(
                    root_chirho,
                    export_chirho,
                    &requested_by_chirho,
                )?;
            println!("{}", serde_json::to_string_pretty(&export_chirho)?);
            Ok(None)
        }
        CommandChirho::PrivacyEraseChirho(args_chirho) => {
            let crate::args_chirho::privacy_args_chirho::PrivacyEraseArgsChirho {
                subject_chirho,
                requested_by_chirho,
                reason_chirho,
            } = args_chirho;
            let record_chirho = privacy_chirho::erase_subject_data_chirho(
                root_chirho,
                &subject_chirho,
                &requested_by_chirho,
                &reason_chirho,
            )?;
            println!(
                "privacy-erasure #{} subject={} requested_by={} removed_keys={}",
                record_chirho.seq_chirho,
                record_chirho.subject_chirho,
                record_chirho.requested_by_chirho,
                record_chirho.removed_keys_chirho
            );
            Ok(None)
        }
        CommandChirho::PrivacyErasureHistoryChirho(args_chirho) => {
            let crate::args_chirho::privacy_args_chirho::PrivacyErasureHistoryArgsChirho {
                subject_chirho,
            } = args_chirho;
            let mut records_chirho =
                privacy_chirho::load_privacy_erasure_records_chirho(root_chirho)?;
            records_chirho.sort_by_key(|record_chirho| record_chirho.seq_chirho);
            let mut shown_chirho = 0_usize;
            for record_chirho in records_chirho {
                if subject_chirho
                    .as_deref()
                    .is_some_and(|subject_chirho| subject_chirho != record_chirho.subject_chirho)
                {
                    continue;
                }
                shown_chirho += 1;
                println!(
                    "#{}\tsubject={}\trequested_by={}\tremoved_keys={}\tat_ms={}",
                    record_chirho.seq_chirho,
                    record_chirho.subject_chirho,
                    record_chirho.requested_by_chirho,
                    record_chirho.removed_keys_chirho,
                    record_chirho.at_ms_chirho
                );
            }
            if shown_chirho == 0 {
                println!("(no privacy erasure records)");
            }
            Ok(None)
        }
        CommandChirho::PrivacyRetentionSweepChirho(args_chirho) => {
            let crate::args_chirho::privacy_args_chirho::PrivacyRetentionSweepArgsChirho {
                retention_days_chirho,
                operator_chirho,
                dry_run_chirho,
            } = args_chirho;
            let sweep_chirho = retention_chirho::sweep_private_blob_retention_chirho(
                root_chirho,
                retention_days_chirho,
                &operator_chirho,
                dry_run_chirho,
            )?;
            println!(
                "privacy-retention retention_days={} cutoff_ms={} expired_blobs={} target_keys={} removed_keys={} held_keys={}{}",
                sweep_chirho.retention_days_chirho,
                sweep_chirho.cutoff_ms_chirho,
                sweep_chirho.expired_blob_seqs_chirho.len(),
                sweep_chirho.target_key_ids_chirho.len(),
                sweep_chirho.removed_key_ids_chirho.len(),
                sweep_chirho.held_key_ids_chirho.len(),
                if sweep_chirho.dry_run_chirho {
                    " dry-run"
                } else {
                    ""
                }
            );
            if let Some(record_chirho) = sweep_chirho.record_chirho {
                println!("  retention record seq=#{}", record_chirho.seq_chirho);
            }
            Ok(None)
        }
        CommandChirho::PrivacyRetentionHistoryChirho => {
            let mut records_chirho =
                retention_chirho::load_private_blob_retention_records_chirho(root_chirho)?;
            records_chirho.sort_by_key(|record_chirho| record_chirho.seq_chirho);
            if records_chirho.is_empty() {
                println!("(no privacy retention history)");
            }
            for record_chirho in records_chirho {
                println!(
                    "#{}\toperator={}\tretention_days={}\tcutoff_ms={}\texpired_blobs={}\ttarget_keys={}\tremoved_keys={}\theld_keys={}\tat_ms={}",
                    record_chirho.seq_chirho,
                    record_chirho.operator_chirho,
                    record_chirho.retention_days_chirho,
                    record_chirho.cutoff_ms_chirho,
                    record_chirho.expired_blob_seqs_chirho.len(),
                    record_chirho.target_key_ids_chirho.len(),
                    record_chirho.removed_key_ids_chirho.len(),
                    record_chirho.held_key_ids_chirho.len(),
                    record_chirho.at_ms_chirho
                );
            }
            Ok(None)
        }
        CommandChirho::PrivacyRetentionVerifyChirho => {
            let count_chirho = retention_chirho::verify_private_blob_retention_chirho(root_chirho)?;
            println!("verified {count_chirho} privacy retention record(s)");
            Ok(None)
        }
        CommandChirho::LegalHoldPlaceChirho(args_chirho) => {
            let crate::args_chirho::privacy_args_chirho::LegalHoldPlaceArgsChirho {
                hold_id_chirho,
                subject_chirho,
                case_ref_chirho,
                reason_chirho,
                operator_chirho,
            } = args_chirho;
            let record_chirho = legal_hold_chirho::place_legal_hold_chirho(
                root_chirho,
                &hold_id_chirho,
                &subject_chirho,
                &case_ref_chirho,
                &reason_chirho,
                &operator_chirho,
            )?;
            println!(
                "legal-hold #{}\thold={}\tsubject={}\tcase={}\taction=place\toperator={}",
                record_chirho.seq_chirho,
                record_chirho.hold_id_chirho,
                record_chirho.subject_chirho,
                record_chirho.case_ref_chirho,
                record_chirho.operator_chirho
            );
            Ok(None)
        }
        CommandChirho::LegalHoldReleaseChirho(args_chirho) => {
            let crate::args_chirho::privacy_args_chirho::LegalHoldReleaseArgsChirho {
                hold_id_chirho,
                reason_chirho,
                operator_chirho,
            } = args_chirho;
            let record_chirho = legal_hold_chirho::release_legal_hold_chirho(
                root_chirho,
                &hold_id_chirho,
                &reason_chirho,
                &operator_chirho,
            )?;
            println!(
                "legal-hold #{}\thold={}\tsubject={}\tcase={}\taction=release\toperator={}",
                record_chirho.seq_chirho,
                record_chirho.hold_id_chirho,
                record_chirho.subject_chirho,
                record_chirho.case_ref_chirho,
                record_chirho.operator_chirho
            );
            Ok(None)
        }
        CommandChirho::LegalHoldsChirho(args_chirho) => {
            let crate::args_chirho::privacy_args_chirho::LegalHoldsArgsChirho { subject_chirho } =
                args_chirho;
            let mut records_chirho =
                legal_hold_chirho::load_legal_hold_records_chirho(root_chirho)?;
            records_chirho.sort_by_key(|record_chirho| record_chirho.seq_chirho);
            let mut shown_chirho = 0_usize;
            for record_chirho in records_chirho {
                if subject_chirho
                    .as_deref()
                    .is_some_and(|subject_chirho| subject_chirho != record_chirho.subject_chirho)
                {
                    continue;
                }
                shown_chirho += 1;
                println!(
                    "#{}\thold={}\tsubject={}\tcase={}\taction={:?}\toperator={}\tat_ms={}",
                    record_chirho.seq_chirho,
                    record_chirho.hold_id_chirho,
                    record_chirho.subject_chirho,
                    record_chirho.case_ref_chirho,
                    record_chirho.action_chirho,
                    record_chirho.operator_chirho,
                    record_chirho.at_ms_chirho
                );
            }
            if shown_chirho == 0 {
                println!("(no legal hold records)");
            }
            Ok(None)
        }
        CommandChirho::LegalHoldVerifyChirho => {
            let report_chirho = legal_hold_chirho::verify_legal_holds_chirho(root_chirho)?;
            println!(
                "verified {} legal hold record(s), {} active hold(s)",
                report_chirho.records_chirho, report_chirho.active_holds_chirho
            );
            Ok(None)
        }
        CommandChirho::PrivacyReplicaRegisterChirho(args_chirho) => {
            let crate::args_chirho::privacy_args_chirho::PrivacyReplicaRegisterArgsChirho {
                replica_chirho,
                replica_root_chirho,
                registered_by_chirho,
            } = args_chirho;
            let record_chirho = privacy_backup_chirho::register_privacy_replica_chirho(
                root_chirho,
                &replica_chirho,
                &replica_root_chirho,
                &registered_by_chirho,
            )?;
            println!(
                "privacy-replica #{}\treplica={}\troot={}\tregistered_by={}",
                record_chirho.seq_chirho,
                record_chirho.replica_chirho,
                record_chirho.root_chirho,
                record_chirho.registered_by_chirho
            );
            Ok(None)
        }
        CommandChirho::PrivacyReplicasChirho => {
            let mut records_chirho =
                privacy_backup_chirho::load_privacy_replica_targets_chirho(root_chirho)?;
            records_chirho.sort_by_key(|record_chirho| record_chirho.seq_chirho);
            if records_chirho.is_empty() {
                println!("(no privacy replicas)");
            }
            for record_chirho in records_chirho {
                println!(
                    "#{}\treplica={}\troot={}\tregistered_by={}\tat_ms={}",
                    record_chirho.seq_chirho,
                    record_chirho.replica_chirho,
                    record_chirho.root_chirho,
                    record_chirho.registered_by_chirho,
                    record_chirho.at_ms_chirho
                );
            }
            Ok(None)
        }
        CommandChirho::PrivacyBackupPolicySetChirho(args_chirho) => {
            let crate::args_chirho::privacy_args_chirho::PrivacyBackupPolicySetArgsChirho {
                scope_chirho,
                declared_by_chirho,
            } = args_chirho;
            let record_chirho = privacy_backup_chirho::declare_privacy_backup_key_policy_chirho(
                root_chirho,
                &scope_chirho,
                &declared_by_chirho,
            )?;
            println!(
                "privacy-backup-policy #{}\tscope={}\tdeclared_by={}\tmax_unregistered_key_material_ttl_ms={}",
                record_chirho.seq_chirho,
                record_chirho.scope_chirho,
                record_chirho.declared_by_chirho,
                record_chirho.max_unregistered_key_material_ttl_ms_chirho
            );
            Ok(None)
        }
        CommandChirho::PrivacyBackupPoliciesChirho => {
            let mut records_chirho =
                privacy_backup_chirho::load_privacy_backup_key_policy_records_chirho(root_chirho)?;
            records_chirho.sort_by_key(|record_chirho| record_chirho.seq_chirho);
            if records_chirho.is_empty() {
                println!("(no privacy backup policies)");
            }
            for record_chirho in records_chirho {
                println!(
                    "#{}\tscope={}\tdeclared_by={}\tmax_unregistered_key_material_ttl_ms={}\tat_ms={}",
                    record_chirho.seq_chirho,
                    record_chirho.scope_chirho,
                    record_chirho.declared_by_chirho,
                    record_chirho.max_unregistered_key_material_ttl_ms_chirho,
                    record_chirho.at_ms_chirho
                );
            }
            Ok(None)
        }
        CommandChirho::PrivacyErasurePropagateChirho(args_chirho) => {
            let crate::args_chirho::privacy_args_chirho::PrivacyErasurePropagateArgsChirho {
                erasure_chirho,
                replica_chirho,
                requested_by_chirho,
            } = args_chirho;
            let record_chirho = privacy_backup_chirho::propagate_privacy_erasure_to_replica_chirho(
                root_chirho,
                erasure_chirho,
                &replica_chirho,
                &requested_by_chirho,
            )?;
            println!(
                "privacy-erasure-propagation #{}\terasure={}\tsubject={}\treplica={}\tremoved_keys={}\talready_missing={}",
                record_chirho.seq_chirho,
                record_chirho.source_erasure_seq_chirho,
                record_chirho.subject_chirho,
                record_chirho.replica_chirho,
                record_chirho.removed_key_ids_chirho.len(),
                record_chirho.already_missing_key_ids_chirho.len()
            );
            Ok(None)
        }
        CommandChirho::PrivacyErasurePropagationsChirho(args_chirho) => {
            let crate::args_chirho::privacy_args_chirho::PrivacyErasurePropagationsArgsChirho {
                subject_chirho,
                replica_chirho,
            } = args_chirho;
            let mut records_chirho =
                privacy_backup_chirho::load_privacy_erasure_propagation_records_chirho(
                    root_chirho,
                )?;
            records_chirho.sort_by_key(|record_chirho| record_chirho.seq_chirho);
            let mut shown_chirho = 0_usize;
            for record_chirho in records_chirho {
                if subject_chirho
                    .as_deref()
                    .is_some_and(|subject_chirho| subject_chirho != record_chirho.subject_chirho)
                {
                    continue;
                }
                if replica_chirho
                    .as_deref()
                    .is_some_and(|replica_chirho| replica_chirho != record_chirho.replica_chirho)
                {
                    continue;
                }
                shown_chirho += 1;
                println!(
                    "#{}\terasure={}\tsubject={}\treplica={}\tremoved_keys={}\talready_missing={}\tat_ms={}",
                    record_chirho.seq_chirho,
                    record_chirho.source_erasure_seq_chirho,
                    record_chirho.subject_chirho,
                    record_chirho.replica_chirho,
                    record_chirho.removed_key_ids_chirho.len(),
                    record_chirho.already_missing_key_ids_chirho.len(),
                    record_chirho.at_ms_chirho
                );
            }
            if shown_chirho == 0 {
                println!("(no privacy erasure propagation records)");
            }
            Ok(None)
        }
        other_chirho => Ok(Some(other_chirho)),
    }
}
