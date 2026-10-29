// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! App/template registry CLI helpers kept out of the large dispatch arm file.

use crate::args_chirho::CommandChirho;
use cairn_chirho::app_chirho;
use cairn_chirho::model_chirho::HashChirho;
use clap::Args;
use std::path::Path;

#[derive(Clone, Debug, Args)]
pub struct TemplateRegistrySetArgsChirho {
    #[arg(long = "template-id")]
    pub template_id_chirho: String,
    #[arg(long = "root-dag")]
    pub root_dag_chirho: String,
    #[arg(long = "response-content-type")]
    pub response_content_type_chirho: String,
}

pub fn handle_template_registry_command_chirho(
    root_chirho: &Path,
    command_chirho: &CommandChirho,
) -> anyhow::Result<bool> {
    match command_chirho {
        CommandChirho::TemplateRegistrySetChirho(args_chirho) => {
            template_registry_set_cli_chirho(root_chirho, args_chirho.clone())?;
            Ok(true)
        }
        CommandChirho::AppVerifyChirho => {
            app_verify_cli_chirho(root_chirho)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

pub fn template_registry_set_cli_chirho(
    root_chirho: &Path,
    args_chirho: TemplateRegistrySetArgsChirho,
) -> anyhow::Result<()> {
    let record_chirho = app_chirho::register_template_app_template_chirho(
        root_chirho,
        app_chirho::TemplateRegistryInputChirho {
            template_id_chirho: args_chirho.template_id_chirho,
            root_dag_chirho: HashChirho(args_chirho.root_dag_chirho),
            response_content_type_chirho: args_chirho.response_content_type_chirho,
        },
    )?;
    let count_chirho = app_chirho::verify_template_registry_chirho(root_chirho)?;
    println!(
        "template registry set '{}' -> dag {} content-type={} seq={}",
        record_chirho.template_id_chirho,
        record_chirho.root_dag_chirho.0,
        record_chirho.response_content_type_chirho,
        record_chirho.seq_chirho
    );
    println!("verified {count_chirho} template registry record(s)");
    Ok(())
}

pub fn app_verify_cli_chirho(root_chirho: &Path) -> anyhow::Result<()> {
    let count_chirho = app_chirho::verify_apps_chirho(root_chirho)?;
    let route_count_chirho = app_chirho::verify_app_routes_chirho(root_chirho)?;
    let input_policy_count_chirho = app_chirho::verify_app_input_policies_chirho(root_chirho)?;
    let root_response_policy_count_chirho =
        app_chirho::verify_app_response_policies_chirho(root_chirho)?;
    let response_policy_count_chirho =
        app_chirho::verify_app_route_response_policies_chirho(root_chirho)?;
    let params_count_chirho = app_chirho::verify_app_params_chirho(root_chirho)?;
    let static_asset_count_chirho = app_chirho::verify_app_static_assets_chirho(root_chirho)?;
    println!(
        "verified {count_chirho} app ownership record(s), {route_count_chirho} app route record(s), {input_policy_count_chirho} app input policy record(s), {root_response_policy_count_chirho} app root response policy record(s), {response_policy_count_chirho} app route response policy record(s), {params_count_chirho} app params record(s), and {static_asset_count_chirho} app static asset record(s)"
    );
    let warnings_chirho = app_chirho::app_input_policy_warnings_chirho(root_chirho)?;
    for warning_chirho in &warnings_chirho {
        let surface_chirho = match &warning_chirho.route_chirho {
            Some(route_chirho) => format!("{}/{}", warning_chirho.app_chirho, route_chirho),
            None => warning_chirho.app_chirho.clone(),
        };
        println!(
            "warning app input policy {surface_chirho}: {}",
            warning_chirho.reason_chirho
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use cairn_chirho::model_chirho::DagChirho;
    use cairn_chirho::store_chirho;

    fn tmp_root_chirho(label_chirho: &str) -> std::path::PathBuf {
        let nanos_chirho = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "cairn-template-registry-cli-{label_chirho}-{nanos_chirho}"
        ))
    }

    #[test]
    fn template_registry_set_cli_registers_and_verifies_template_chirho() {
        let root_chirho = tmp_root_chirho("set");
        let dag_hash_chirho = store_chirho::put_object_chirho(
            &root_chirho,
            &DagChirho {
                nodes_chirho: Vec::new(),
                edges_chirho: Vec::new(),
            },
        )
        .unwrap();
        template_registry_set_cli_chirho(
            &root_chirho,
            TemplateRegistrySetArgsChirho {
                template_id_chirho: "tree-template-landing-chirho".to_string(),
                root_dag_chirho: dag_hash_chirho.0.clone(),
                response_content_type_chirho: "text/html; charset=utf-8".to_string(),
            },
        )
        .unwrap();
        let registry_chirho = app_chirho::verified_template_registry_chirho(&root_chirho).unwrap();
        let target_chirho = registry_chirho.get("tree-template-landing-chirho").unwrap();
        assert_eq!(target_chirho.root_dag_chirho, dag_hash_chirho);
        assert_eq!(
            target_chirho.response_content_type_chirho,
            "text/html; charset=utf-8"
        );
    }
}
