// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Maintenance, publish, and read-model inspection CLI command handlers.

use crate::args_chirho::CommandChirho;
use cairn_chirho::model_chirho::HashChirho;
use cairn_chirho::{gc_chirho, publish_chirho, query_chirho};
use std::path::Path;

pub(crate) fn handle_maintenance_command_chirho(
    root_chirho: &Path,
    command_chirho: &CommandChirho,
) -> anyhow::Result<bool> {
    match command_chirho {
        CommandChirho::PublishChirho(args_chirho) => {
            let crate::args_chirho::ops_args_chirho::PublishArgsChirho {
                name_chirho,
                dag_chirho,
                owner_chirho,
                server_chirho,
                token_chirho,
            } = args_chirho;
            let package_chirho = publish_chirho::build_package_chirho(
                root_chirho,
                name_chirho,
                &HashChirho(dag_chirho.clone()),
                owner_chirho,
            )?;
            let body_chirho = serde_json::to_string(&package_chirho)?;
            let url_chirho = format!("{}/publish-chirho", server_chirho.trim_end_matches('/'));
            let mut request_chirho =
                ureq::post(&url_chirho).set("content-type", "application/json");
            if let Some(token_val_chirho) = token_chirho {
                request_chirho =
                    request_chirho.set("authorization", &format!("Bearer {token_val_chirho}"));
            }
            match request_chirho.send_string(&body_chirho) {
                Ok(response_chirho) => {
                    println!(
                        "{}",
                        response_chirho.into_string().unwrap_or_default().trim_end()
                    );
                }
                Err(e_chirho) => eprintln!("publish failed: {e_chirho}"),
            }
            Ok(true)
        }
        CommandChirho::GcChirho => {
            let report_chirho = gc_chirho::gc_chirho(root_chirho)?;
            println!(
                "gc: collected {} objects, kept {}",
                report_chirho.collected_chirho, report_chirho.kept_chirho
            );
            Ok(true)
        }
        CommandChirho::ProjectChirho(args_chirho) => {
            let crate::args_chirho::ops_args_chirho::ProjectArgsChirho { at_chirho } = args_chirho;
            let n_chirho = match at_chirho {
                Some(view_chirho) => query_chirho::project_at_chirho(root_chirho, *view_chirho)?,
                None => query_chirho::project_chirho(root_chirho)?,
            };
            println!("projected {n_chirho} entries into the read model");
            Ok(true)
        }
        CommandChirho::QueryChirho { sql_chirho } => {
            let rows_chirho = query_chirho::query_chirho(root_chirho, sql_chirho)?;
            for row_chirho in &rows_chirho {
                println!("{}", row_chirho.join("\t"));
            }
            println!("({} rows)", rows_chirho.len());
            Ok(true)
        }
        _ => Ok(false),
    }
}
