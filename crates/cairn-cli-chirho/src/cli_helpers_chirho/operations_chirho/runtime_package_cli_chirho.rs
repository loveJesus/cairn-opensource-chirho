// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Runtime-package CLI smoke helpers split out of dispatch_chirho.rs.

use crate::args_chirho::CommandChirho;
use cairn_chirho::model_chirho::HashChirho;
use cairn_chirho::{cas_chirho, runner_chirho, runtime_profile_chirho};
use std::path::Path;

pub(crate) const RUNTIME_PACKAGE_SMOKE_REPORT_SCHEMA_CHIRHO: &str =
    "runtime-package-smoke-report-v1-chirho";
pub(crate) const RUNTIME_PACKAGE_SMOKE_EXECUTION_SCHEMA_CHIRHO: &str =
    "runtime-package-smoke-execution-v1-chirho";
const RUNTIME_PACKAGE_SMOKE_EXECUTION_FUEL_LIMIT_CHIRHO: u64 = 1_000_000;

pub(crate) fn handle_runtime_package_command_chirho(
    root_chirho: &Path,
    command_chirho: &CommandChirho,
) -> anyhow::Result<bool> {
    match command_chirho {
        CommandChirho::RuntimePackageBuildChirho(args_chirho) => {
            let crate::args_chirho::core_args_chirho::RuntimePackageBuildArgsChirho {
                module_chirho,
                profile_chirho,
            } = args_chirho;
            let profile_kind_chirho =
                runtime_profile_chirho::parse_runtime_profile_kind_chirho(profile_chirho)?;
            let (package_chirho, package_hash_chirho) =
                runtime_profile_chirho::build_runtime_package_chirho(
                    root_chirho,
                    &HashChirho(module_chirho.clone()),
                    profile_kind_chirho,
                )?;
            println!("package {}", package_hash_chirho.0);
            println!("profile {:?}", package_chirho.profile_chirho);
            println!("executable {}", package_chirho.executable_chirho.0);
            println!("objects {}", package_chirho.object_hashes_chirho.len());
            Ok(true)
        }
        CommandChirho::RuntimePackageShowChirho { package_chirho } => {
            let package_obj_chirho = runtime_profile_chirho::load_runtime_package_chirho(
                root_chirho,
                &HashChirho(package_chirho.clone()),
            )?;
            println!("{}", serde_json::to_string_pretty(&package_obj_chirho)?);
            Ok(true)
        }
        CommandChirho::RuntimePackageCheckChirho { package_chirho } => {
            let package_obj_chirho =
                runtime_profile_chirho::validate_stored_runtime_package_chirho(
                    root_chirho,
                    &HashChirho(package_chirho.clone()),
                )?;
            println!(
                "runtime package OK: profile={:?} executable={} objects={} included={} excluded={}",
                package_obj_chirho.profile_chirho,
                package_obj_chirho.executable_chirho.0,
                package_obj_chirho.object_hashes_chirho.len(),
                package_obj_chirho.included_items_chirho.len(),
                package_obj_chirho.excluded_items_chirho.len()
            );
            Ok(true)
        }
        CommandChirho::RuntimePackageSmokeChirho(args_chirho) => {
            let crate::args_chirho::core_args_chirho::RuntimePackageSmokeArgsChirho {
                package_chirho,
                server_chirho,
                json_chirho,
                input_chirho,
                expect_output_chirho,
            } = args_chirho;
            if input_chirho.is_none() && expect_output_chirho.is_some() {
                anyhow::bail!("--expect-output requires --input so the smoke has a payload to run");
            }
            let input_bytes_chirho = input_chirho
                .as_ref()
                .map(|input_chirho| input_chirho.as_bytes());
            let expect_output_bytes_chirho = expect_output_chirho
                .as_ref()
                .map(|output_chirho| output_chirho.as_bytes());
            let report_chirho = smoke_runtime_package_artifacts_chirho(
                root_chirho,
                server_chirho,
                &HashChirho(package_chirho.clone()),
                input_bytes_chirho,
                expect_output_bytes_chirho,
            )?;
            if *json_chirho {
                println!("{}", serde_json::to_string_pretty(&report_chirho)?);
            } else {
                println!(
                    "runtime package artifact smoke OK: package={} profile={:?} executable={} bytes={} server={}",
                    report_chirho.package_chirho.0,
                    report_chirho.profile_chirho,
                    report_chirho.executable_chirho.0,
                    report_chirho.executable_bytes_chirho,
                    report_chirho.server_chirho
                );
                println!("entry {}", report_chirho.entry_chirho);
                println!("manifest {}", report_chirho.manifest_url_chirho);
                println!("executable {}", report_chirho.executable_url_chirho);
                if let Some(execution_chirho) = &report_chirho.execution_chirho {
                    println!(
                        "execution entry={} input={} bytes output={} bytes fuel={}/{}",
                        execution_chirho.entry_chirho,
                        execution_chirho.input_bytes_chirho,
                        execution_chirho.output_bytes_chirho,
                        execution_chirho.fuel_used_chirho,
                        execution_chirho.fuel_limit_chirho
                    );
                    println!(
                        "execution hashes input={} output={}",
                        execution_chirho.input_chirho.0, execution_chirho.output_chirho.0
                    );
                    if let Some(expected_output_chirho) = &execution_chirho.expected_output_chirho {
                        println!("expected output {} match=true", expected_output_chirho.0);
                    }
                }
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct RuntimePackageSmokeReportChirho {
    pub(crate) schema_chirho: &'static str,
    pub(crate) package_chirho: HashChirho,
    pub(crate) profile_chirho: runtime_profile_chirho::RuntimeProfileKindChirho,
    pub(crate) executable_chirho: HashChirho,
    pub(crate) entry_chirho: String,
    pub(crate) executable_bytes_chirho: usize,
    pub(crate) server_chirho: String,
    pub(crate) manifest_url_chirho: String,
    pub(crate) manifest_content_type_chirho: String,
    pub(crate) executable_url_chirho: String,
    pub(crate) executable_content_type_chirho: String,
    pub(crate) execution_chirho: Option<RuntimePackageSmokeExecutionChirho>,
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct RuntimePackageSmokeExecutionChirho {
    pub(crate) schema_chirho: &'static str,
    pub(crate) entry_chirho: String,
    pub(crate) input_bytes_chirho: usize,
    pub(crate) input_chirho: HashChirho,
    pub(crate) output_bytes_chirho: usize,
    pub(crate) output_chirho: HashChirho,
    pub(crate) expected_output_chirho: Option<HashChirho>,
    pub(crate) expected_output_matches_chirho: Option<bool>,
    pub(crate) fuel_limit_chirho: u64,
    pub(crate) fuel_used_chirho: u64,
}

pub(crate) fn smoke_runtime_package_artifacts_chirho(
    root_chirho: &Path,
    server_chirho: &str,
    package_hash_chirho: &HashChirho,
    execution_input_chirho: Option<&[u8]>,
    expected_output_chirho: Option<&[u8]>,
) -> anyhow::Result<RuntimePackageSmokeReportChirho> {
    if execution_input_chirho.is_none() && expected_output_chirho.is_some() {
        anyhow::bail!("runtime package execution expectation requires an input payload");
    }
    let local_package_chirho = runtime_profile_chirho::validate_stored_runtime_package_chirho(
        root_chirho,
        package_hash_chirho,
    )?;
    runtime_profile_chirho::ensure_public_runtime_package_artifact_chirho(&local_package_chirho)?;
    let local_executable_chirho =
        cas_chirho::get_chirho(root_chirho, &local_package_chirho.executable_chirho)?;
    let base_chirho = server_chirho.trim_end_matches('/');
    let manifest_url_chirho = format!(
        "{base_chirho}/runtime-package-chirho/{}/manifest-chirho",
        package_hash_chirho.0
    );
    let executable_url_chirho = format!(
        "{base_chirho}/runtime-package-chirho/{}/executable-chirho",
        package_hash_chirho.0
    );

    let manifest_response_chirho = ureq::get(&manifest_url_chirho)
        .call()
        .map_err(|e_chirho| anyhow::anyhow!("runtime package manifest smoke failed: {e_chirho}"))?;
    let manifest_content_type_chirho = manifest_response_chirho
        .header("content-type")
        .unwrap_or("")
        .to_string();
    if !manifest_content_type_chirho.starts_with("application/json") {
        anyhow::bail!(
            "runtime package manifest returned content-type '{}', expected application/json",
            manifest_content_type_chirho
        );
    }
    let remote_package_chirho: runtime_profile_chirho::RuntimePackageChirho =
        serde_json::from_str(&manifest_response_chirho.into_string()?)?;
    if remote_package_chirho != local_package_chirho {
        anyhow::bail!("remote runtime package manifest does not match the local validated package");
    }

    let executable_response_chirho =
        ureq::get(&executable_url_chirho)
            .call()
            .map_err(|e_chirho| {
                anyhow::anyhow!("runtime package executable smoke failed: {e_chirho}")
            })?;
    let executable_content_type_chirho = executable_response_chirho
        .header("content-type")
        .unwrap_or("")
        .to_string();
    if executable_content_type_chirho != "application/wasm" {
        anyhow::bail!(
            "runtime package executable returned content-type '{}', expected application/wasm",
            executable_content_type_chirho
        );
    }
    let mut executable_reader_chirho = executable_response_chirho.into_reader();
    let mut executable_bytes_chirho = Vec::new();
    std::io::Read::read_to_end(&mut executable_reader_chirho, &mut executable_bytes_chirho)?;
    let executable_hash_chirho = cas_chirho::hash_chirho(&executable_bytes_chirho);
    if executable_hash_chirho != local_package_chirho.executable_chirho {
        anyhow::bail!(
            "runtime package executable body hash {} does not match manifest executable {}",
            executable_hash_chirho.0,
            local_package_chirho.executable_chirho.0
        );
    }
    if executable_bytes_chirho != local_executable_chirho {
        anyhow::bail!("runtime package executable body does not match local CAS bytes");
    }

    let execution_chirho = smoke_runtime_package_execution_chirho(
        &local_package_chirho,
        &executable_bytes_chirho,
        execution_input_chirho,
        expected_output_chirho,
    )?;

    Ok(RuntimePackageSmokeReportChirho {
        schema_chirho: RUNTIME_PACKAGE_SMOKE_REPORT_SCHEMA_CHIRHO,
        package_chirho: package_hash_chirho.clone(),
        profile_chirho: local_package_chirho.profile_chirho,
        executable_chirho: local_package_chirho.executable_chirho,
        entry_chirho: local_package_chirho.entry_chirho,
        executable_bytes_chirho: executable_bytes_chirho.len(),
        server_chirho: base_chirho.to_string(),
        manifest_url_chirho,
        manifest_content_type_chirho,
        executable_url_chirho,
        executable_content_type_chirho,
        execution_chirho,
    })
}

fn smoke_runtime_package_execution_chirho(
    package_chirho: &runtime_profile_chirho::RuntimePackageChirho,
    executable_bytes_chirho: &[u8],
    execution_input_chirho: Option<&[u8]>,
    expected_output_chirho: Option<&[u8]>,
) -> anyhow::Result<Option<RuntimePackageSmokeExecutionChirho>> {
    let Some(input_chirho) = execution_input_chirho else {
        return Ok(None);
    };
    let outcome_chirho = runner_chirho::run_node_bytes_chirho(
        executable_bytes_chirho,
        &package_chirho.entry_chirho,
        input_chirho,
        RUNTIME_PACKAGE_SMOKE_EXECUTION_FUEL_LIMIT_CHIRHO,
    )?;
    let expected_output_hash_chirho = expected_output_chirho.map(cas_chirho::hash_chirho);
    let expected_output_matches_chirho = expected_output_chirho
        .map(|expected_chirho| expected_chirho == outcome_chirho.output_chirho.as_slice());
    if expected_output_matches_chirho == Some(false) {
        anyhow::bail!(
            "runtime package execution output hash {} did not match expected output hash {}",
            cas_chirho::hash_chirho(&outcome_chirho.output_chirho).0,
            expected_output_hash_chirho
                .as_ref()
                .map(|hash_chirho| hash_chirho.0.as_str())
                .unwrap_or("<missing>")
        );
    }
    Ok(Some(RuntimePackageSmokeExecutionChirho {
        schema_chirho: RUNTIME_PACKAGE_SMOKE_EXECUTION_SCHEMA_CHIRHO,
        entry_chirho: package_chirho.entry_chirho.clone(),
        input_bytes_chirho: input_chirho.len(),
        input_chirho: cas_chirho::hash_chirho(input_chirho),
        output_bytes_chirho: outcome_chirho.output_chirho.len(),
        output_chirho: cas_chirho::hash_chirho(&outcome_chirho.output_chirho),
        expected_output_chirho: expected_output_hash_chirho,
        expected_output_matches_chirho,
        fuel_limit_chirho: RUNTIME_PACKAGE_SMOKE_EXECUTION_FUEL_LIMIT_CHIRHO,
        fuel_used_chirho: outcome_chirho.fuel_used_chirho,
    }))
}
