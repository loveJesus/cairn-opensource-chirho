// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Index and provenance-index CLI command handlers.

use crate::args_chirho::CommandChirho;
use cairn_chirho::index_chirho;
use cairn_chirho::model_chirho::HashChirho;
use std::path::Path;

pub(crate) fn handle_index_command_chirho(
    root_chirho: &Path,
    command_chirho: &CommandChirho,
) -> anyhow::Result<bool> {
    match command_chirho {
        CommandChirho::IndexProjectChirho(args_chirho) => {
            let crate::args_chirho::state_args_chirho::IndexProjectArgsChirho { at_chirho } =
                args_chirho;
            let projection_chirho = index_chirho::project_index_chirho(root_chirho, *at_chirho)?;
            println!(
                "index {} -> root {} view=v{} rows={} ref={}",
                projection_chirho.record_hash_chirho.0,
                projection_chirho.record_chirho.root_chirho.0,
                projection_chirho.record_chirho.view_chirho,
                projection_chirho.record_chirho.rows_chirho,
                index_chirho::index_ref_chirho()
            );
            Ok(true)
        }
        CommandChirho::IndexGetChirho(args_chirho) => {
            let crate::args_chirho::state_args_chirho::IndexGetArgsChirho {
                root_chirho: record_chirho,
                key_chirho,
            } = args_chirho;
            match index_chirho::get_index_value_chirho(
                root_chirho,
                &HashChirho(record_chirho.clone()),
                key_chirho,
            )? {
                Some(value_chirho) => println!("{}", String::from_utf8_lossy(&value_chirho)),
                None => println!("(absent)"),
            }
            Ok(true)
        }
        CommandChirho::IndexRollbackChirho {
            root_chirho: record_chirho,
        } => {
            let record_chirho = index_chirho::rollback_index_ref_chirho(
                root_chirho,
                &HashChirho(record_chirho.clone()),
            )?;
            println!(
                "{} -> view=v{} root={} rows={}",
                index_chirho::index_ref_chirho(),
                record_chirho.view_chirho,
                record_chirho.root_chirho.0,
                record_chirho.rows_chirho
            );
            Ok(true)
        }
        CommandChirho::IndexVerifyChirho {
            root_chirho: record_chirho,
        } => {
            let report_chirho =
                index_chirho::verify_index_chirho(root_chirho, &HashChirho(record_chirho.clone()))?;
            println!(
                "index verified: nodes={} rows={}",
                report_chirho.nodes_chirho, report_chirho.rows_chirho
            );
            Ok(true)
        }
        CommandChirho::IndexProvenanceProjectChirho => {
            let projection_chirho =
                index_chirho::project_inverted_provenance_index_chirho(root_chirho)?;
            println!(
                "provenance-index {} -> root {} runs={} rows={} ref={}",
                projection_chirho.record_hash_chirho.0,
                projection_chirho.record_chirho.root_chirho.0,
                projection_chirho.record_chirho.runs_indexed_chirho,
                projection_chirho.record_chirho.rows_chirho,
                index_chirho::provenance_index_ref_chirho()
            );
            Ok(true)
        }
        CommandChirho::IndexProvenanceFindChirho(args_chirho) => {
            let crate::args_chirho::state_args_chirho::IndexProvenanceFindArgsChirho {
                root_chirho: record_chirho,
                state_chirho,
            } = args_chirho;
            let effects_chirho = index_chirho::find_dependent_effects_chirho(
                root_chirho,
                &HashChirho(record_chirho.clone()),
                &HashChirho(state_chirho.clone()),
            )?;
            for effect_chirho in &effects_chirho {
                let response_chirho = effect_chirho
                    .response_chirho
                    .as_ref()
                    .map(|hash_chirho| hash_chirho.0.as_str())
                    .unwrap_or("(pending)");
                println!(
                    "run={} effect_seq={} cap={:?} request={} response={}",
                    effect_chirho.run_chirho.0,
                    effect_chirho.effect_seq_chirho,
                    effect_chirho.capability_chirho,
                    effect_chirho.request_chirho.0,
                    response_chirho
                );
            }
            println!("({} dependent effects)", effects_chirho.len());
            Ok(true)
        }
        CommandChirho::IndexProvenanceVerifyChirho {
            root_chirho: record_chirho,
        } => {
            let report_chirho = index_chirho::verify_inverted_provenance_index_chirho(
                root_chirho,
                &HashChirho(record_chirho.clone()),
            )?;
            println!(
                "provenance-index verified: nodes={} rows={} runs={}",
                report_chirho.nodes_chirho,
                report_chirho.rows_chirho,
                report_chirho.runs_indexed_chirho
            );
            Ok(true)
        }
        _ => Ok(false),
    }
}
