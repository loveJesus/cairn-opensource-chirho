// For God so loved the world, that He gave His only begotten Son, that whosoever believeth in Him should not perish, but have everlasting life. — John 3:16 (KJV)

//! SP13 source-platform smoke: execute the guide rail through review, serve, rollback, and negatives.
//!
//! Workflow: spec-chirho/workflows-chirho/learner-tier-zero-key-classroom-chirho.md.

use serde::Serialize;
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SOURCE_PLATFORM_SMOKE_SCHEMA_CHIRHO: &str = "source-platform-smoke-report-v1-chirho";
const STARTER_APP_CHIRHO: &str = "starter-contact-chirho";
const STARTER_TENANT_CHIRHO: &str = "starter-contact-chirho";
const STARTER_ASSET_CHIRHO: &str = "starter-contact-chirho.css";
const OWNER_CREDENTIAL_CHIRHO: &str = "sp13-owner-credential-chirho";
const STEP_TOTAL_CHIRHO: usize = SOURCE_PLATFORM_SMOKE_GUIDE_COMMANDS_CHIRHO.len();

#[cfg(test)]
const SOURCE_PLATFORM_SMOKE_GUIDE_START_CHIRHO: &str =
    "<!-- source-platform-smoke-commands-chirho:start -->";
#[cfg(test)]
const SOURCE_PLATFORM_SMOKE_GUIDE_END_CHIRHO: &str =
    "<!-- source-platform-smoke-commands-chirho:end -->";

pub(crate) const SOURCE_PLATFORM_SMOKE_GUIDE_COMMANDS_CHIRHO: &[&str] = &[
    "cargo build -p cairn-cli-chirho --bin cairn-chirho -p cairn-tree-build-chirho --bin tree-build-chirho",
    "$TB new contact-form-chirho \"$APP_ROOT\"",
    "$TB check --json \"$APP_ROOT\"",
    "( cd \"$APP_ROOT\" && cargo build -q --example render_contact_form_guest_chirho --target wasm32-unknown-unknown )",
    "$TB test --json \"$APP_ROOT\"",
    "$TB watch \"$APP_ROOT\" --cycles 1 --skip-guest-build --json",
    "$TB emit \"$APP_ROOT\" > \"$APP_ROOT/.emitted-manifest-chirho.json\"",
    "$CLI --root \"$RUNTIME_ROOT\" --tenant starter-contact-chirho identity-register --kind owner --credential \"$OWNER_CREDENTIAL\"",
    "$CLI --root \"$RUNTIME_ROOT\" --tenant starter-contact-chirho app-source-review --manifest \"$APP_ROOT/.emitted-manifest-chirho.json\" --owner \"$OWNER\" --json",
    "$CLI --root \"$RUNTIME_ROOT\" --tenant starter-contact-chirho review-promote --app starter-contact-chirho --owner \"$OWNER\" --candidate \"$CANDIDATE\" --source-review-report \"$SOURCE_REVIEW_REPORT\"",
    "$CLI --root \"$RUNTIME_ROOT\" --tenant starter-contact-chirho serve --port \"$PORT\"",
    "POST /app-chirho/starter-contact-chirho/",
    "GET /app-assets-chirho/starter-contact-chirho/by-name-chirho/starter-contact-chirho.css",
    "POST /app-review-chirho/owner/<id>/starter-contact-chirho/rollback-chirho",
    "GET /app-assets-chirho/starter-contact-chirho/by-name-chirho/starter-contact-chirho.css",
    "$CLI --root \"$NEGATIVE_ROOT\" agent-authored-backend-smoke --json",
];

#[derive(Clone, Debug)]
struct SmokeOptionsChirho {
    json_chirho: bool,
    cairn_cli_chirho: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize)]
struct SourcePlatformSmokeReportChirho {
    schema_chirho: &'static str,
    ok_chirho: bool,
    local_only_chirho: bool,
    persisted_new_artifact_family_chirho: bool,
    step_count_run_chirho: usize,
    step_count_total_chirho: usize,
    guide_command_count_chirho: usize,
    guide_commands_chirho: Vec<&'static str>,
    app_chirho: &'static str,
    tenant_chirho: &'static str,
    reviewed_candidate_chirho: String,
    source_review_report_chirho: String,
    route_status_chirho: u16,
    asset_status_before_rollback_chirho: u16,
    rollback_status_chirho: u16,
    asset_status_after_rollback_chirho: u16,
    overcap_blocked_chirho: bool,
    undeclared_effect_blocked_chirho: bool,
    persistent_effect_records_chirho: u64,
    volatile_effect_records_chirho: u64,
    negative_smoke_schema_chirho: String,
    steps_chirho: Vec<SmokeStepChirho>,
}

#[derive(Clone, Debug, Serialize)]
struct SmokeStepChirho {
    index_chirho: usize,
    command_chirho: &'static str,
    ok_chirho: bool,
    detail_chirho: String,
}

#[derive(Clone, Debug)]
struct HttpResponseChirho {
    status_chirho: u16,
    body_chirho: Vec<u8>,
}

struct ServerGuardChirho {
    child_chirho: Child,
}

impl Drop for ServerGuardChirho {
    fn drop(&mut self) {
        let _ = self.child_chirho.kill();
        let _ = self.child_chirho.wait();
    }
}

pub(crate) fn cmd_source_platform_smoke_chirho(args_chirho: &[String]) -> ExitCode {
    let options_chirho = match parse_options_chirho(args_chirho) {
        Ok(options_chirho) => options_chirho,
        Err(error_chirho) => {
            eprintln!("{error_chirho}");
            return ExitCode::from(2);
        }
    };
    match run_source_platform_smoke_chirho(&options_chirho) {
        Ok(report_chirho) => {
            if options_chirho.json_chirho {
                println!("{}", serde_json::to_string_pretty(&report_chirho).unwrap());
            } else {
                println!(
                    "source-platform-smoke: clean ({}/{})",
                    report_chirho.step_count_run_chirho, report_chirho.step_count_total_chirho
                );
            }
            ExitCode::SUCCESS
        }
        Err(error_chirho) => {
            if options_chirho.json_chirho {
                println!(
                    "{}",
                    serde_json::json!({
                        "schema_chirho": SOURCE_PLATFORM_SMOKE_SCHEMA_CHIRHO,
                        "ok_chirho": false,
                        "error_chirho": error_chirho,
                    })
                );
            } else {
                eprintln!("source-platform-smoke: {error_chirho}");
            }
            ExitCode::FAILURE
        }
    }
}

fn parse_options_chirho(args_chirho: &[String]) -> Result<SmokeOptionsChirho, String> {
    let mut json_chirho = false;
    let mut cairn_cli_chirho = None;
    let mut i_chirho = 2;
    while i_chirho < args_chirho.len() {
        match args_chirho[i_chirho].as_str() {
            "--json" => {
                json_chirho = true;
                i_chirho += 1;
            }
            "--cairn-cli" => {
                let value_chirho = args_chirho
                    .get(i_chirho + 1)
                    .ok_or_else(|| "error: --cairn-cli requires a path".to_string())?;
                cairn_cli_chirho = Some(PathBuf::from(value_chirho));
                i_chirho += 2;
            }
            other_chirho => {
                return Err(format!(
                    "error: unknown source-platform-smoke argument '{other_chirho}'"
                ));
            }
        }
    }
    if !json_chirho {
        return Err(
            "usage: tree-build-chirho source-platform-smoke --json [--cairn-cli <path>]"
                .to_string(),
        );
    }
    Ok(SmokeOptionsChirho {
        json_chirho,
        cairn_cli_chirho,
    })
}

fn run_source_platform_smoke_chirho(
    options_chirho: &SmokeOptionsChirho,
) -> Result<SourcePlatformSmokeReportChirho, String> {
    let tree_build_chirho = current_tree_build_binary_chirho()?;
    let cairn_cli_chirho = options_chirho
        .cairn_cli_chirho
        .clone()
        .unwrap_or(resolve_cairn_cli_binary_chirho()?);
    if !cairn_cli_chirho.exists() {
        return Err(format!(
            "cairn CLI not found at {}; run the guide build command first or pass --cairn-cli",
            cairn_cli_chirho.display()
        ));
    }

    let app_root_chirho = tmp_dir_chirho("sp13-source-platform-app-chirho")?;
    let runtime_root_chirho = tmp_dir_chirho("sp13-source-platform-root-chirho")?;
    let negative_root_chirho = tmp_dir_chirho("sp13-source-platform-negative-root-chirho")?;
    let cleanup_roots_chirho = std::env::var("CAIRN_SOURCE_PLATFORM_SMOKE_KEEP_ROOTS_CHIRHO")
        .ok()
        .as_deref()
        != Some("1");
    let mut steps_chirho = Vec::new();
    let mut step_index_chirho = 0usize;

    push_step_chirho(
        &mut steps_chirho,
        &mut step_index_chirho,
        0,
        "already built before invoking this command",
    );
    run_step_chirho(
        &tree_build_chirho,
        &[
            "new",
            "contact-form-chirho",
            path_str_chirho(&app_root_chirho)?,
        ],
        None,
        &mut steps_chirho,
        &mut step_index_chirho,
        1,
    )?;
    let check_chirho = run_step_chirho(
        &tree_build_chirho,
        &["check", "--json", path_str_chirho(&app_root_chirho)?],
        None,
        &mut steps_chirho,
        &mut step_index_chirho,
        2,
    )?;
    let check_json_chirho = json_from_stdout_chirho(&check_chirho, "check --json")?;
    if check_json_chirho["finding_count_chirho"].as_u64() != Some(0) {
        return Err("fresh scaffold did not check clean".to_string());
    }
    run_step_chirho(
        "cargo",
        &[
            "build",
            "-q",
            "--example",
            "render_contact_form_guest_chirho",
            "--target",
            "wasm32-unknown-unknown",
        ],
        Some(&app_root_chirho),
        &mut steps_chirho,
        &mut step_index_chirho,
        3,
    )?;
    let test_chirho = run_step_chirho(
        &tree_build_chirho,
        &["test", "--json", path_str_chirho(&app_root_chirho)?],
        None,
        &mut steps_chirho,
        &mut step_index_chirho,
        4,
    )?;
    if json_from_stdout_chirho(&test_chirho, "test --json")?["clean_chirho"].as_bool() != Some(true)
    {
        return Err("fresh scaffold node tests did not pass".to_string());
    }
    let watch_chirho = run_step_chirho(
        &tree_build_chirho,
        &[
            "watch",
            path_str_chirho(&app_root_chirho)?,
            "--cycles",
            "1",
            "--skip-guest-build",
            "--json",
        ],
        None,
        &mut steps_chirho,
        &mut step_index_chirho,
        5,
    )?;
    if json_from_stdout_chirho(&watch_chirho, "watch --json")?["clean_chirho"].as_bool()
        != Some(true)
    {
        return Err("fresh scaffold watch cycle was not clean".to_string());
    }
    let manifest_path_chirho = app_root_chirho.join(".emitted-manifest-chirho.json");
    let emit_chirho = run_step_chirho(
        &tree_build_chirho,
        &["emit", path_str_chirho(&app_root_chirho)?],
        None,
        &mut steps_chirho,
        &mut step_index_chirho,
        6,
    )?;
    std::fs::write(&manifest_path_chirho, &emit_chirho.stdout_chirho)
        .map_err(|e_chirho| e_chirho.to_string())?;

    let register_chirho = run_step_chirho(
        &cairn_cli_chirho,
        &[
            "--root",
            path_str_chirho(&runtime_root_chirho)?,
            "--tenant",
            STARTER_TENANT_CHIRHO,
            "identity-register",
            "--kind",
            "owner",
            "--credential",
            OWNER_CREDENTIAL_CHIRHO,
        ],
        None,
        &mut steps_chirho,
        &mut step_index_chirho,
        7,
    )?;
    let owner_chirho = first_field_chirho(&register_chirho.stdout_chirho, "identity-register")?;
    let review_chirho = run_step_chirho(
        &cairn_cli_chirho,
        &[
            "--root",
            path_str_chirho(&runtime_root_chirho)?,
            "--tenant",
            STARTER_TENANT_CHIRHO,
            "app-source-review",
            "--manifest",
            path_str_chirho(&manifest_path_chirho)?,
            "--owner",
            &owner_chirho,
            "--json",
        ],
        None,
        &mut steps_chirho,
        &mut step_index_chirho,
        8,
    )?;
    let review_json_chirho = json_from_stdout_chirho(&review_chirho, "app-source-review --json")?;
    let candidate_chirho = review_json_chirho["candidate_chirho"]["root_dag_chirho"]
        .as_str()
        .ok_or_else(|| "review report missing candidate root_dag_chirho".to_string())?
        .to_string();
    let source_review_report_chirho = review_json_chirho["source_review_report_chirho"]
        .as_str()
        .ok_or_else(|| "review report missing source_review_report_chirho".to_string())?
        .to_string();
    run_step_chirho(
        &cairn_cli_chirho,
        &[
            "--root",
            path_str_chirho(&runtime_root_chirho)?,
            "--tenant",
            STARTER_TENANT_CHIRHO,
            "review-promote",
            "--app",
            STARTER_APP_CHIRHO,
            "--owner",
            &owner_chirho,
            "--candidate",
            &candidate_chirho,
            "--source-review-report",
            &source_review_report_chirho,
        ],
        None,
        &mut steps_chirho,
        &mut step_index_chirho,
        9,
    )?;

    let port_chirho = unused_local_port_chirho()?;
    let server_chirho = start_server_chirho(
        &cairn_cli_chirho,
        &runtime_root_chirho,
        STARTER_TENANT_CHIRHO,
        port_chirho,
    )?;
    push_step_chirho(
        &mut steps_chirho,
        &mut step_index_chirho,
        10,
        &format!("served on 127.0.0.1:{port_chirho}"),
    );
    wait_for_health_chirho(port_chirho)?;
    let route_response_chirho = http_request_chirho(
        "POST",
        port_chirho,
        &format!("/app-chirho/{STARTER_APP_CHIRHO}/"),
        &[("content-type", "application/json")],
        b"{}",
    )?;
    if route_response_chirho.status_chirho != 200
        || !String::from_utf8_lossy(&route_response_chirho.body_chirho).contains("Contact us")
    {
        return Err(format!(
            "served route failed: status={} body={}",
            route_response_chirho.status_chirho,
            String::from_utf8_lossy(&route_response_chirho.body_chirho)
        ));
    }
    push_step_chirho(
        &mut steps_chirho,
        &mut step_index_chirho,
        11,
        &format!("status {}", route_response_chirho.status_chirho),
    );
    let asset_path_chirho =
        format!("/app-assets-chirho/{STARTER_APP_CHIRHO}/by-name-chirho/{STARTER_ASSET_CHIRHO}");
    let asset_before_chirho =
        http_request_chirho("GET", port_chirho, &asset_path_chirho, &[], &[])?;
    if asset_before_chirho.status_chirho != 302 {
        return Err(format!(
            "reviewed by-name asset was not installed: status={}",
            asset_before_chirho.status_chirho
        ));
    }
    push_step_chirho(
        &mut steps_chirho,
        &mut step_index_chirho,
        12,
        &format!("status {}", asset_before_chirho.status_chirho),
    );

    let token_chirho = login_token_chirho(
        &cairn_cli_chirho,
        &runtime_root_chirho,
        STARTER_TENANT_CHIRHO,
        &owner_chirho,
    )?;
    let owner_id_chirho = owner_chirho
        .strip_prefix("owner/")
        .ok_or_else(|| format!("owner principal had unexpected shape: {owner_chirho}"))?;
    let rollback_body_chirho = format!("source_review_report_chirho={source_review_report_chirho}");
    let rollback_path_chirho =
        format!("/app-review-chirho/owner/{owner_id_chirho}/{STARTER_APP_CHIRHO}/rollback-chirho");
    let auth_header_chirho = format!("Bearer {token_chirho}");
    let rollback_chirho = http_request_chirho(
        "POST",
        port_chirho,
        &rollback_path_chirho,
        &[
            ("authorization", auth_header_chirho.as_str()),
            (
                "content-type",
                "application/x-www-form-urlencoded; charset=utf-8",
            ),
        ],
        rollback_body_chirho.as_bytes(),
    )?;
    if rollback_chirho.status_chirho != 200
        || !String::from_utf8_lossy(&rollback_chirho.body_chirho)
            .contains("data-app-review-rollback-chirho=\"ok\"")
    {
        return Err(format!(
            "review rollback failed: status={}",
            rollback_chirho.status_chirho
        ));
    }
    push_step_chirho(
        &mut steps_chirho,
        &mut step_index_chirho,
        13,
        &format!("status {}", rollback_chirho.status_chirho),
    );
    let asset_after_chirho = http_request_chirho("GET", port_chirho, &asset_path_chirho, &[], &[])?;
    if asset_after_chirho.status_chirho != 404 {
        return Err(format!(
            "review rollback did not remove by-name asset: status={}",
            asset_after_chirho.status_chirho
        ));
    }
    push_step_chirho(
        &mut steps_chirho,
        &mut step_index_chirho,
        14,
        &format!("status {}", asset_after_chirho.status_chirho),
    );
    drop(server_chirho);

    let negative_chirho = run_step_chirho(
        &cairn_cli_chirho,
        &[
            "--root",
            path_str_chirho(&negative_root_chirho)?,
            "agent-authored-backend-smoke",
            "--json",
        ],
        None,
        &mut steps_chirho,
        &mut step_index_chirho,
        15,
    )?;
    let negative_json_chirho =
        json_from_stdout_chirho(&negative_chirho, "agent-authored-backend-smoke --json")?;
    let persistent_effect_records_chirho = negative_json_chirho["persistent_effect_records_chirho"]
        .as_u64()
        .ok_or_else(|| "negative smoke missing persistent effect count".to_string())?;
    let volatile_effect_records_chirho = negative_json_chirho["volatile_effect_records_chirho"]
        .as_u64()
        .ok_or_else(|| "negative smoke missing volatile effect count".to_string())?;
    let overcap_blocked_chirho =
        negative_json_chirho["overcap_promotion_rejected_chirho"].as_bool() == Some(true)
            && negative_json_chirho["overcap_app_ref_absent_chirho"].as_bool() == Some(true);
    let undeclared_effect_blocked_chirho =
        negative_json_chirho["undeclared_effect_runtime_blocked_chirho"].as_bool() == Some(true);
    if !overcap_blocked_chirho
        || !undeclared_effect_blocked_chirho
        || persistent_effect_records_chirho != 0
        || volatile_effect_records_chirho != 0
    {
        return Err(
            "agent-authored negative smoke did not prove blocked zero-effect posture".to_string(),
        );
    }

    if cleanup_roots_chirho {
        let _ = std::fs::remove_dir_all(&app_root_chirho);
        let _ = std::fs::remove_dir_all(&runtime_root_chirho);
        let _ = std::fs::remove_dir_all(&negative_root_chirho);
    }

    Ok(SourcePlatformSmokeReportChirho {
        schema_chirho: SOURCE_PLATFORM_SMOKE_SCHEMA_CHIRHO,
        ok_chirho: true,
        local_only_chirho: true,
        persisted_new_artifact_family_chirho: false,
        step_count_run_chirho: steps_chirho.len(),
        step_count_total_chirho: STEP_TOTAL_CHIRHO,
        guide_command_count_chirho: SOURCE_PLATFORM_SMOKE_GUIDE_COMMANDS_CHIRHO.len(),
        guide_commands_chirho: SOURCE_PLATFORM_SMOKE_GUIDE_COMMANDS_CHIRHO.to_vec(),
        app_chirho: STARTER_APP_CHIRHO,
        tenant_chirho: STARTER_TENANT_CHIRHO,
        reviewed_candidate_chirho: candidate_chirho,
        source_review_report_chirho,
        route_status_chirho: route_response_chirho.status_chirho,
        asset_status_before_rollback_chirho: asset_before_chirho.status_chirho,
        rollback_status_chirho: rollback_chirho.status_chirho,
        asset_status_after_rollback_chirho: asset_after_chirho.status_chirho,
        overcap_blocked_chirho,
        undeclared_effect_blocked_chirho,
        persistent_effect_records_chirho,
        volatile_effect_records_chirho,
        negative_smoke_schema_chirho: negative_json_chirho["schema_chirho"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        steps_chirho,
    })
}

fn run_step_chirho<P: AsRef<Path>>(
    program_chirho: P,
    args_chirho: &[&str],
    cwd_chirho: Option<&Path>,
    steps_chirho: &mut Vec<SmokeStepChirho>,
    step_index_chirho: &mut usize,
    command_index_chirho: usize,
) -> Result<CommandOutputChirho, String> {
    let output_chirho = Command::new(program_chirho.as_ref())
        .args(args_chirho)
        .current_dir(cwd_chirho.unwrap_or_else(|| Path::new(".")))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e_chirho| e_chirho.to_string())?;
    let ok_chirho = output_chirho.status.success();
    push_step_chirho(
        steps_chirho,
        step_index_chirho,
        command_index_chirho,
        &format!(
            "exit={} stdout_bytes={} stderr_bytes={}",
            output_chirho.status.code().unwrap_or(-1),
            output_chirho.stdout.len(),
            output_chirho.stderr.len()
        ),
    );
    if !ok_chirho {
        return Err(format!(
            "command failed: {}\nstderr: {}",
            SOURCE_PLATFORM_SMOKE_GUIDE_COMMANDS_CHIRHO[command_index_chirho],
            String::from_utf8_lossy(&output_chirho.stderr)
        ));
    }
    Ok(CommandOutputChirho {
        stdout_chirho: output_chirho.stdout,
    })
}

#[derive(Clone, Debug)]
struct CommandOutputChirho {
    stdout_chirho: Vec<u8>,
}

fn push_step_chirho(
    steps_chirho: &mut Vec<SmokeStepChirho>,
    step_index_chirho: &mut usize,
    command_index_chirho: usize,
    detail_chirho: &str,
) {
    *step_index_chirho += 1;
    steps_chirho.push(SmokeStepChirho {
        index_chirho: *step_index_chirho,
        command_chirho: SOURCE_PLATFORM_SMOKE_GUIDE_COMMANDS_CHIRHO[command_index_chirho],
        ok_chirho: true,
        detail_chirho: detail_chirho.to_string(),
    });
}

fn json_from_stdout_chirho(
    output_chirho: &CommandOutputChirho,
    label_chirho: &str,
) -> Result<Value, String> {
    serde_json::from_slice(&output_chirho.stdout_chirho)
        .map_err(|e_chirho| format!("{label_chirho} emitted invalid JSON: {e_chirho}"))
}

fn first_field_chirho(bytes_chirho: &[u8], label_chirho: &str) -> Result<String, String> {
    let text_chirho = String::from_utf8_lossy(bytes_chirho);
    text_chirho
        .lines()
        .next()
        .and_then(|line_chirho| line_chirho.split('\t').next())
        .filter(|field_chirho| !field_chirho.is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("{label_chirho} emitted no first field"))
}

fn login_token_chirho(
    cli_chirho: &Path,
    root_chirho: &Path,
    tenant_chirho: &str,
    owner_chirho: &str,
) -> Result<String, String> {
    let root_text_chirho = path_str_chirho(root_chirho)?;
    let output_chirho = Command::new(cli_chirho)
        .args([
            "--root",
            root_text_chirho,
            "--tenant",
            tenant_chirho,
            "identity-login",
            owner_chirho,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e_chirho| e_chirho.to_string())?;
    if !output_chirho.status.success() {
        return Err(format!(
            "identity-login failed: {}",
            String::from_utf8_lossy(&output_chirho.stderr)
        ));
    }
    let text_chirho = String::from_utf8_lossy(&output_chirho.stdout);
    text_chirho
        .split('\t')
        .find_map(|field_chirho| field_chirho.strip_prefix("token="))
        .map(str::to_string)
        .ok_or_else(|| "identity-login emitted no token field".to_string())
}

fn start_server_chirho(
    cli_chirho: &Path,
    root_chirho: &Path,
    tenant_chirho: &str,
    port_chirho: u16,
) -> Result<ServerGuardChirho, String> {
    let child_chirho = Command::new(cli_chirho)
        .args([
            "--root",
            path_str_chirho(root_chirho)?,
            "--tenant",
            tenant_chirho,
            "serve",
            "--port",
            &port_chirho.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e_chirho| e_chirho.to_string())?;
    Ok(ServerGuardChirho { child_chirho })
}

fn wait_for_health_chirho(port_chirho: u16) -> Result<(), String> {
    for _ in 0..100 {
        match http_request_chirho("GET", port_chirho, "/healthz-chirho", &[], &[]) {
            Ok(response_chirho) if response_chirho.status_chirho == 200 => return Ok(()),
            _ => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    Err("server did not become healthy".to_string())
}

fn http_request_chirho(
    method_chirho: &str,
    port_chirho: u16,
    path_chirho: &str,
    headers_chirho: &[(&str, &str)],
    body_chirho: &[u8],
) -> Result<HttpResponseChirho, String> {
    let mut stream_chirho =
        TcpStream::connect(("127.0.0.1", port_chirho)).map_err(|e_chirho| e_chirho.to_string())?;
    stream_chirho
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e_chirho| e_chirho.to_string())?;
    let mut request_chirho = format!(
        "{method_chirho} {path_chirho} HTTP/1.1\r\nHost: 127.0.0.1:{port_chirho}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body_chirho.len()
    );
    for (name_chirho, value_chirho) in headers_chirho {
        request_chirho.push_str(name_chirho);
        request_chirho.push_str(": ");
        request_chirho.push_str(value_chirho);
        request_chirho.push_str("\r\n");
    }
    request_chirho.push_str("\r\n");
    stream_chirho
        .write_all(request_chirho.as_bytes())
        .map_err(|e_chirho| e_chirho.to_string())?;
    stream_chirho
        .write_all(body_chirho)
        .map_err(|e_chirho| e_chirho.to_string())?;
    let mut response_chirho = Vec::new();
    stream_chirho
        .read_to_end(&mut response_chirho)
        .map_err(|e_chirho| e_chirho.to_string())?;
    parse_http_response_chirho(&response_chirho)
}

fn parse_http_response_chirho(bytes_chirho: &[u8]) -> Result<HttpResponseChirho, String> {
    let split_chirho = bytes_chirho
        .windows(4)
        .position(|window_chirho| window_chirho == b"\r\n\r\n")
        .ok_or_else(|| "HTTP response missing header terminator".to_string())?;
    let header_bytes_chirho = &bytes_chirho[..split_chirho];
    let body_chirho = bytes_chirho[split_chirho + 4..].to_vec();
    let header_text_chirho = String::from_utf8_lossy(header_bytes_chirho);
    let mut lines_chirho = header_text_chirho.lines();
    let status_line_chirho = lines_chirho
        .next()
        .ok_or_else(|| "HTTP response missing status line".to_string())?;
    let status_chirho = status_line_chirho
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| "HTTP response status line malformed".to_string())?
        .parse::<u16>()
        .map_err(|e_chirho| e_chirho.to_string())?;
    Ok(HttpResponseChirho {
        status_chirho,
        body_chirho,
    })
}

fn unused_local_port_chirho() -> Result<u16, String> {
    let listener_chirho =
        TcpListener::bind("127.0.0.1:0").map_err(|e_chirho| e_chirho.to_string())?;
    let port_chirho = listener_chirho
        .local_addr()
        .map_err(|e_chirho| e_chirho.to_string())?
        .port();
    drop(listener_chirho);
    Ok(port_chirho)
}

fn current_tree_build_binary_chirho() -> Result<PathBuf, String> {
    std::env::current_exe().map_err(|e_chirho| e_chirho.to_string())
}

fn resolve_cairn_cli_binary_chirho() -> Result<PathBuf, String> {
    if let Ok(path_chirho) = std::env::var("CAIRN_CLI_BIN_CHIRHO") {
        return Ok(PathBuf::from(path_chirho));
    }
    let manifest_chirho = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_chirho = manifest_chirho
        .ancestors()
        .nth(3)
        .ok_or_else(|| "tree-build crate is not under the expected workspace".to_string())?;
    let target_dir_chirho = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace_chirho.join("target"));
    Ok(target_dir_chirho.join("debug").join("cairn-chirho"))
}

fn tmp_dir_chirho(prefix_chirho: &str) -> Result<PathBuf, String> {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let now_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e_chirho| e_chirho.to_string())?
        .as_nanos();
    let dir_chirho = std::env::temp_dir().join(format!("{prefix_chirho}-{now_chirho}-{n_chirho}"));
    std::fs::create_dir_all(&dir_chirho).map_err(|e_chirho| e_chirho.to_string())?;
    Ok(dir_chirho)
}

fn path_str_chirho(path_chirho: &Path) -> Result<&str, String> {
    path_chirho
        .to_str()
        .ok_or_else(|| format!("path is not UTF-8: {}", path_chirho.display()))
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn guide_command_block_matches_smoke_commands_chirho() {
        let guide_chirho = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .ancestors()
                .nth(3)
                .unwrap()
                .join("docs-chirho/AUTHORING-chirho.md"),
        )
        .unwrap();
        let block_chirho = guide_chirho
            .split(SOURCE_PLATFORM_SMOKE_GUIDE_START_CHIRHO)
            .nth(1)
            .and_then(|tail_chirho| {
                tail_chirho
                    .split(SOURCE_PLATFORM_SMOKE_GUIDE_END_CHIRHO)
                    .next()
            })
            .expect("AUTHORING guide must contain source platform smoke command block");
        let commands_chirho = block_chirho
            .lines()
            .map(str::trim)
            .filter(|line_chirho| !line_chirho.is_empty())
            .filter(|line_chirho| !line_chirho.starts_with("```"))
            .collect::<Vec<_>>();
        assert_eq!(commands_chirho, SOURCE_PLATFORM_SMOKE_GUIDE_COMMANDS_CHIRHO);
    }
}
