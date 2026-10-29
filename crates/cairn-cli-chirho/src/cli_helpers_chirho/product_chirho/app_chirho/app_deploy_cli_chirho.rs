// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! App deploy and route deploy CLI helpers split out of dispatch_chirho.rs.

use crate::args_chirho::CommandChirho;
use anyhow::bail;
use cairn_chirho::model_chirho::HashChirho;
use cairn_chirho::{app_chirho, app_manifest_chirho, app_source_manifest_chirho};
use std::path::Path;

pub(crate) fn handle_app_deploy_command_chirho(
    root_chirho: &Path,
    command_chirho: CommandChirho,
) -> anyhow::Result<Option<CommandChirho>> {
    match command_chirho {
        CommandChirho::DeployChirho(args_chirho) => {
            let crate::args_chirho::app_args_chirho::DeployArgsChirho {
                name_chirho,
                dag_chirho,
                owner_chirho,
            } = args_chirho;
            app_chirho::deploy_app_chirho(
                root_chirho,
                &name_chirho,
                HashChirho(dag_chirho.clone()),
                &owner_chirho,
            )?;
            println!(
                "deployed '{name_chirho}' -> dag {dag_chirho} owner={owner_chirho}  (route /app-chirho/{name_chirho})"
            );
            Ok(None)
        }
        CommandChirho::AppManifestDeployChirho { manifest_chirho } => {
            let manifest_text_chirho = std::fs::read_to_string(&manifest_chirho)?;
            let manifest_obj_chirho: app_manifest_chirho::AppDeployManifestChirho =
                serde_json::from_str(&manifest_text_chirho)?;
            let report_chirho =
                app_manifest_chirho::deploy_app_manifest_chirho(root_chirho, &manifest_obj_chirho)?;
            println!(
                "manifest deployed app '{}' owner={}",
                report_chirho.app_chirho, report_chirho.owner_chirho
            );
            if let Some(dag_chirho) = &report_chirho.root_dag_chirho {
                println!("app dag {}", dag_chirho.0);
            }
            for route_chirho in &report_chirho.routes_chirho {
                println!(
                    "route {} -> dag {}",
                    route_chirho.route_chirho, route_chirho.dag_chirho.0
                );
            }
            for package_chirho in &report_chirho.runtime_packages_chirho {
                println!(
                    "runtime package {:?} module={} package={} executable={}",
                    package_chirho.profile_chirho,
                    package_chirho.module_chirho.0,
                    package_chirho.package_chirho.0,
                    package_chirho.executable_chirho.0
                );
            }
            Ok(None)
        }
        CommandChirho::AppSourceDeployChirho(args_chirho) => {
            let crate::args_chirho::app_args_chirho::AppSourceDeployArgsChirho {
                manifest_chirho,
                owner_chirho,
                allow_unreviewed_dev_chirho,
            } = args_chirho;
            if !allow_unreviewed_dev_chirho {
                bail!(
                    "app-source-deploy moves live refs without review; use app-source-review + review-promote, or pass --allow-unreviewed-dev for a labeled local dev bypass"
                );
            }
            let report_chirho = if let Some(owner_chirho) = owner_chirho {
                app_source_manifest_chirho::deploy_app_source_manifest_from_path_for_owner_unreviewed_dev_chirho(
                    root_chirho,
                    &manifest_chirho,
                    &owner_chirho,
                )?
            } else {
                app_source_manifest_chirho::deploy_app_source_manifest_from_path_unreviewed_dev_chirho(
                    root_chirho,
                    &manifest_chirho,
                )?
            };
            println!(
                "source manifest deployed app '{}' owner={}",
                report_chirho.app_chirho, report_chirho.owner_chirho
            );
            if report_chirho.unreviewed_dev_chirho {
                println!(
                    "unreviewed-dev-bypass=true header={} value={}",
                    app_chirho::APP_UNREVIEWED_DEV_HEADER_CHIRHO,
                    app_chirho::APP_UNREVIEWED_DEV_HEADER_VALUE_CHIRHO
                );
            }
            for node_chirho in &report_chirho.nodes_chirho {
                println!(
                    "node {} -> {}",
                    node_chirho.id_chirho, node_chirho.node_chirho.0
                );
            }
            for dag_chirho in &report_chirho.dags_chirho {
                println!(
                    "dag {} -> {}",
                    dag_chirho.id_chirho, dag_chirho.dag_chirho.0
                );
            }
            for module_chirho in &report_chirho.modules_chirho {
                println!(
                    "module {} -> {} dag {}",
                    module_chirho.id_chirho,
                    module_chirho.module_chirho.0,
                    module_chirho.dag_chirho.0
                );
            }
            if let Some(deploy_chirho) = &report_chirho.deploy_chirho {
                if let Some(dag_chirho) = &deploy_chirho.root_dag_chirho {
                    println!("app dag {}", dag_chirho.0);
                }
                for route_chirho in &deploy_chirho.routes_chirho {
                    println!(
                        "route {} -> dag {}",
                        route_chirho.route_chirho, route_chirho.dag_chirho.0
                    );
                }
                for package_chirho in &deploy_chirho.runtime_packages_chirho {
                    println!(
                        "runtime package {:?} module={} package={} executable={}",
                        package_chirho.profile_chirho,
                        package_chirho.module_chirho.0,
                        package_chirho.package_chirho.0,
                        package_chirho.executable_chirho.0
                    );
                }
            }
            if let Some(package_chirho) = &report_chirho.package_chirho {
                println!(
                    "publish package {} app={} dag={} objects={}",
                    package_chirho.package_hash_chirho.0,
                    package_chirho.app_chirho,
                    package_chirho.dag_chirho.0,
                    package_chirho.objects_chirho
                );
            }
            match &report_chirho.target_chirho {
                app_source_manifest_chirho::AppSourceDeployTargetReportChirho::LocalDeployChirho => {
                    println!("target local-deploy");
                }
                app_source_manifest_chirho::AppSourceDeployTargetReportChirho::LocalInstallChirho {
                    root_chirho,
                    objects_installed_chirho,
                } => {
                    println!(
                        "target local-install root={} objects_installed={}",
                        root_chirho.display(),
                        objects_installed_chirho
                    );
                }
                app_source_manifest_chirho::AppSourceDeployTargetReportChirho::HttpPublishChirho {
                    server_chirho,
                    status_chirho,
                    response_chirho,
                } => {
                    println!("target http-publish server={server_chirho} status={status_chirho}");
                    if !response_chirho.trim().is_empty() {
                        println!("{}", response_chirho.trim_end());
                    }
                }
            }
            Ok(None)
        }
        CommandChirho::AppRouteDeployChirho(args_chirho) => {
            let crate::args_chirho::app_args_chirho::AppRouteDeployArgsChirho {
                app_chirho,
                route_chirho,
                dag_chirho,
                owner_chirho,
            } = args_chirho;
            app_chirho::deploy_app_route_chirho(
                root_chirho,
                &app_chirho,
                &route_chirho,
                HashChirho(dag_chirho.clone()),
                &owner_chirho,
            )?;
            println!(
                "deployed app route '{app_chirho}/{route_chirho}' -> dag {dag_chirho} owner={owner_chirho}"
            );
            Ok(None)
        }
        CommandChirho::AppRouteUndeployChirho(args_chirho) => {
            let crate::args_chirho::app_args_chirho::AppRouteUndeployArgsChirho {
                app_chirho,
                route_chirho,
                owner_chirho,
            } = args_chirho;
            let removed_chirho = app_chirho::undeploy_app_route_chirho(
                root_chirho,
                &app_chirho,
                &route_chirho,
                &owner_chirho,
            )?;
            if removed_chirho {
                println!("undeployed app route '{app_chirho}/{route_chirho}'");
            } else {
                println!("no deployed app route '{app_chirho}/{route_chirho}'");
            }
            Ok(None)
        }
        CommandChirho::UndeployChirho(args_chirho) => {
            let crate::args_chirho::app_args_chirho::UndeployArgsChirho {
                name_chirho,
                owner_chirho,
            } = args_chirho;
            let removed_chirho =
                app_chirho::undeploy_app_chirho(root_chirho, &name_chirho, &owner_chirho)?;
            if removed_chirho {
                println!("undeployed app '{name_chirho}' (objects remain; gc reclaims them)");
            } else {
                println!("no deployed app '{name_chirho}'");
            }
            Ok(None)
        }
        other_chirho => Ok(Some(other_chirho)),
    }
}
