// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
use crate::args_chirho::CommandChirho;
use cairn_chirho::model_chirho::HashChirho;
use cairn_chirho::{audit_chirho, cache_chirho, verify_chirho};
use cairn_run_intent_preflight_chirho::run_run_intent_startup_preflight_command_chirho as run_intent_preflight_command_chirho;
use std::{fmt::Debug, path::Path};
pub(crate) fn handle_run_audit_command_chirho(
    root_chirho: &Path,
    command_chirho: &CommandChirho,
) -> anyhow::Result<bool> {
    match command_chirho {
        CommandChirho::RunShowChirho { id_chirho } => {
            match cache_chirho::load_result_chirho(root_chirho, &HashChirho(id_chirho.clone()))? {
                Some(result_chirho) => {
                    println!("run     {}", result_chirho.run_chirho.0);
                    println!("status  {:?}", result_chirho.status_chirho);
                    println!("fuel    {}", result_chirho.fuel_used_chirho);
                    for (port_chirho, hash_chirho) in &result_chirho.outputs_chirho {
                        println!("output  {port_chirho} -> {}", hash_chirho.0);
                    }
                    println!("effects {}", result_chirho.effects_chirho.len());
                    println!("trace   {}", result_chirho.trace_chirho.0);
                    for parent_chirho in &result_chirho.parents_chirho {
                        println!("parent  {}", parent_chirho.0);
                    }
                }
                None => eprintln!("no run '{id_chirho}' in the store"),
            }
            Ok(true)
        }
        CommandChirho::InspectChirho { id_chirho } => {
            let hash_chirho = HashChirho(id_chirho.clone());
            match cache_chirho::load_result_chirho(root_chirho, &hash_chirho)? {
                Some(result_chirho) => {
                    println!("run     {}", result_chirho.run_chirho.0);
                    println!("status  {:?}", result_chirho.status_chirho);
                    println!("fuel    {}", result_chirho.fuel_used_chirho);
                    println!("trace   {}", result_chirho.trace_chirho.0);
                    for (port_chirho, h_chirho) in &result_chirho.outputs_chirho {
                        println!("output  {port_chirho} -> {}", h_chirho.0);
                    }
                    println!("effects ({}):", result_chirho.effects_chirho.len());
                    for eff_chirho in &result_chirho.effects_chirho {
                        let idem_chirho = &eff_chirho.idem_key_chirho.0;
                        let sig_chirho = &eff_chirho.sig_chirho;
                        println!(
                            "  - {:?} idem={} sig={}…",
                            eff_chirho.capability_chirho,
                            &idem_chirho[..idem_chirho.len().min(16)],
                            &sig_chirho[..sig_chirho.len().min(16)]
                        );
                    }
                    let chain_chirho = audit_chirho::audit_chirho(root_chirho, &hash_chirho)?;
                    println!(
                        "provenance: {} run(s) in the chain  (audit {id_chirho} = the tree; verify {id_chirho} = check hashes+sigs; reflog / dashboard = the timeline)",
                        chain_chirho.len()
                    );
                }
                None => eprintln!("no run '{id_chirho}' in the store"),
            }
            Ok(true)
        }
        CommandChirho::AuditChirho { id_chirho } => {
            let chain_chirho =
                audit_chirho::audit_chirho(root_chirho, &HashChirho(id_chirho.clone()))?;
            for entry_chirho in &chain_chirho {
                let indent_chirho = "  ".repeat(entry_chirho.depth_chirho);
                match &entry_chirho.result_chirho {
                    Some(r_chirho) => {
                        println!(
                            "{indent_chirho}run {} [{:?}] fuel={} effects={}",
                            &entry_chirho.run_chirho.0[..16],
                            r_chirho.status_chirho,
                            r_chirho.fuel_used_chirho,
                            r_chirho.effects_chirho.len()
                        );
                        for eff_chirho in &r_chirho.effects_chirho {
                            println!(
                                "{indent_chirho}  effect {:?} idem={} sig={}…",
                                eff_chirho.capability_chirho,
                                &eff_chirho.idem_key_chirho.0[..16],
                                &eff_chirho.sig_chirho[..16]
                            );
                        }
                    }
                    None => println!(
                        "{indent_chirho}run {} (not stored — volatile effect)",
                        &entry_chirho.run_chirho.0[..16]
                    ),
                }
            }
            Ok(true)
        }
        CommandChirho::VerifyChirho { id_chirho } => {
            let checked_chirho =
                verify_chirho::verify_chirho(root_chirho, &HashChirho(id_chirho.clone()))?;
            println!(
                "verified: {checked_chirho} run/cache/CAS records checked + all effect signatures OK"
            );
            Ok(true)
        }
        CommandChirho::RunCacheVerifyChirho(args_chirho) => {
            let crate::args_chirho::core_args_chirho::RunCacheVerifyArgsChirho { json_chirho } =
                args_chirho;
            let report_chirho = verify_chirho::inspect_run_cache_chirho(root_chirho)?;
            if *json_chirho {
                println!("{}", serde_json::to_string_pretty(&report_chirho)?);
            } else {
                println!(
                    "run cache: {} persisted run results + {} RunKeyChirho sidecars + {} signed RunResultChirho seals",
                    report_chirho.runs_chirho,
                    report_chirho.runkeys_chirho,
                    report_chirho.runseals_chirho
                );
                print_nonempty_debug_chirho(
                    "missing RunKeyChirho sidecars",
                    &report_chirho.missing_runkeys_chirho,
                );
                print_nonempty_debug_chirho(
                    "run result coordinate mismatches",
                    &report_chirho.result_run_mismatches_chirho,
                );
                print_nonempty_debug_chirho(
                    "RunResultChirho seal failures",
                    &report_chirho.run_result_seal_failures_chirho,
                );
                print_nonempty_debug_chirho(
                    "RunKeyChirho hash mismatches",
                    &report_chirho.runkey_hash_mismatches_chirho,
                );
                print_nonempty_debug_chirho(
                    "RunKeyChirho component failures",
                    &report_chirho.runkey_component_failures_chirho,
                );
                print_count_if_nonzero_chirho(
                    "orphan RunKeyChirho sidecars",
                    report_chirho.orphan_runkeys_chirho.len(),
                    "allowed for volatile/non-persisted runs",
                );
                print_count_if_nonzero_chirho(
                    "orphan RunResultChirho seals",
                    report_chirho.orphan_runseals_chirho.len(),
                    "allowed; ignored without persisted run results",
                );
            }
            verify_chirho::ensure_run_cache_report_clean_chirho(&report_chirho)?;
            if !*json_chirho {
                println!(
                    "verified: persisted run results are signed and bound to RunKeyChirho sidecars"
                );
            }
            Ok(true)
        }
        CommandChirho::RunIntentStartupPreflightChirho(args_chirho) => handled_chirho(
            run_intent_preflight_command_chirho(root_chirho, args_chirho),
        ),
        _ => Ok(false),
    }
}
fn handled_chirho(result_chirho: anyhow::Result<()>) -> anyhow::Result<bool> {
    result_chirho?;
    Ok(true)
}
fn print_nonempty_debug_chirho<T: Debug>(label_chirho: &str, rows_chirho: &[T]) {
    if !rows_chirho.is_empty() {
        println!("{label_chirho}: {rows_chirho:?}");
    }
}
fn print_count_if_nonzero_chirho(label_chirho: &str, count_chirho: usize, note_chirho: &str) {
    if count_chirho > 0 {
        println!("{label_chirho}: {count_chirho} ({note_chirho})");
    }
}
