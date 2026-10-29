// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Owns the component fixture's birth, real-runtime lifetime and private evidence boundary.
//!
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/transient-review-fixture-chirho/lifecycle-source-chirho.md`.

mod authority_chirho;
mod inputs_chirho;
mod ownership_chirho;
mod snapshot_chirho;
#[cfg(test)]
mod tests_chirho;

use anyhow::{ensure, Result};
use cairn_chirho::{app_source_manifest_chirho, identity_chirho, review_chirho};
use cairn_serve_runtime_chirho::{
    ConfiguredLedgerHostRuntimePortsChirho, ServedWriteRelayDestinationSlotChirho,
};
use inputs_chirho::InputsChirho;
use ownership_chirho::{
    absent_chirho, private_input_chirho, private_parent_chirho, session_output_chirho,
    write_session_chirho, OwnedRootChirho,
};
use serde::Serialize;
use snapshot_chirho::SnapshotChirho;
#[cfg(test)]
use snapshot_chirho::{snapshot_chirho, SENTINEL_CHIRHO, SENTINEL_PATH_CHIRHO};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

struct ArgumentsChirho {
    root_chirho: PathBuf,
    tenant_chirho: String,
    manifest_chirho: PathBuf,
    credential_chirho: PathBuf,
    session_chirho: PathBuf,
    stop_chirho: PathBuf,
    port_chirho: u16,
}

impl ArgumentsChirho {
    fn parse_chirho(args_chirho: Vec<OsString>) -> Result<Self> {
        ensure!(args_chirho.len() == 14, "fixture arguments");
        let mut flags_chirho = BTreeMap::new();
        for pair_chirho in args_chirho.chunks_exact(2) {
            let key_chirho = pair_chirho[0]
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("fixture flag"))?;
            ensure!(
                flags_chirho
                    .insert(key_chirho.to_string(), pair_chirho[1].clone())
                    .is_none(),
                "repeated flag"
            );
        }
        let mut take_chirho = |flag_chirho: &str| {
            flags_chirho
                .remove(flag_chirho)
                .ok_or_else(|| anyhow::anyhow!("missing flag"))
        };
        let arguments_chirho = Self {
            root_chirho: take_chirho("--root-chirho")?.into(),
            tenant_chirho: take_chirho("--tenant-chirho")?
                .into_string()
                .map_err(|_| anyhow::anyhow!("tenant encoding"))?,
            manifest_chirho: take_chirho("--manifest-chirho")?.into(),
            credential_chirho: take_chirho("--credential-file-chirho")?.into(),
            session_chirho: take_chirho("--session-out-chirho")?.into(),
            stop_chirho: take_chirho("--stop-file-chirho")?.into(),
            port_chirho: take_chirho("--port-chirho")?
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("port encoding"))?
                .parse()?,
        };
        ensure!(flags_chirho.is_empty(), "unknown flag");
        ensure!(
            cairn_chirho::tenant_chirho::validate_tenant_id_chirho(
                &arguments_chirho.tenant_chirho
            )? == arguments_chirho.tenant_chirho,
            "tenant is not canonical"
        );
        for path_chirho in [
            &arguments_chirho.root_chirho,
            &arguments_chirho.session_chirho,
            &arguments_chirho.stop_chirho,
        ] {
            private_parent_chirho(path_chirho)?;
            absent_chirho(path_chirho)?;
        }
        ensure!(
            arguments_chirho.root_chirho != arguments_chirho.session_chirho
                && arguments_chirho.root_chirho != arguments_chirho.stop_chirho
                && arguments_chirho.session_chirho != arguments_chirho.stop_chirho,
            "overlapping fixture outputs"
        );
        for path_chirho in [
            &arguments_chirho.manifest_chirho,
            &arguments_chirho.credential_chirho,
        ] {
            ensure!(
                path_chirho.is_absolute()
                    && !path_chirho
                        .canonicalize()?
                        .starts_with(&arguments_chirho.root_chirho),
                "fixture input outside root required"
            );
            ensure!(
                path_chirho != &arguments_chirho.session_chirho
                    && path_chirho != &arguments_chirho.stop_chirho,
                "overlapping fixture input"
            );
        }
        Ok(arguments_chirho)
    }
}

#[derive(Serialize)]
struct FrameChirho<'a> {
    schema_chirho: &'static str,
    phase_chirho: &'static str,
    read_authority_test_double_chirho: bool,
    runtime_commit_chirho: &'static str,
    manifest_blake3_chirho: &'a str,
    node_artifacts_blake3_chirho: &'a str,
    candidate_blake3_chirho: &'a str,
    listener_chirho: Option<String>,
    snapshot_chirho: Option<&'a SnapshotChirho>,
}

fn emit_chirho(
    phase_chirho: &'static str,
    inputs_chirho: &InputsChirho,
    candidate_chirho: &str,
    listener_chirho: Option<String>,
    snapshot_chirho: Option<&SnapshotChirho>,
) -> Result<()> {
    let mut output_chirho = std::io::stdout().lock();
    serde_json::to_writer(
        &mut output_chirho,
        &FrameChirho {
            schema_chirho: "transient-review-fixture-v1-chirho",
            phase_chirho,
            read_authority_test_double_chirho: true,
            runtime_commit_chirho: env!("CAIRN_BUILD_COMMIT_CHIRHO"),
            manifest_blake3_chirho: &inputs_chirho.manifest_digest_chirho,
            node_artifacts_blake3_chirho: &inputs_chirho.artifact_digest_chirho,
            candidate_blake3_chirho: candidate_chirho,
            listener_chirho,
            snapshot_chirho,
        },
    )?;
    output_chirho.write_all(b"\n")?;
    output_chirho.flush()?;
    Ok(())
}

pub(super) async fn run_chirho(args_chirho: Vec<OsString>) -> Result<()> {
    let args_chirho = ArgumentsChirho::parse_chirho(args_chirho)?;
    let credential_chirho = zeroize::Zeroizing::new(String::from_utf8(private_input_chirho(
        &args_chirho.credential_chirho,
        4096,
    )?)?);
    ensure!(
        identity_chirho::credential_meets_floor_chirho(&credential_chirho),
        "credential floor"
    );
    let inputs_chirho = InputsChirho::read_chirho(&args_chirho.manifest_chirho)?;
    let listener_chirho =
        tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, args_chirho.port_chirho))
            .await?;
    // Output reservation is create-new and outside the snapshot tree. No existing output is altered.
    let session_chirho = session_output_chirho(&args_chirho.session_chirho)?;
    let owned_chirho =
        OwnedRootChirho::create_chirho(&args_chirho.root_chirho, &args_chirho.tenant_chirho)?
            .activate_chirho()?;
    let root_chirho = owned_chirho.tenant_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )?
    .principal_chirho;
    let user_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
        &credential_chirho,
    )?
    .principal_chirho;
    let report_chirho =
        app_source_manifest_chirho::build_app_source_review_from_prepared_bytes_for_owner_chirho(
            &root_chirho,
            &inputs_chirho.bytes_chirho,
            &inputs_chirho.base_chirho,
            &owner_chirho,
            &inputs_chirho.prepared_chirho,
        )?;
    ensure!(
        report_chirho
            .candidate_chirho
            .routes_chirho
            .iter()
            .any(|route_chirho| route_chirho
                .input_mode_chirho
                .as_ref()
                .is_some_and(cairn_model_app_chirho::app_request_input_chirho::allows_transient_request_user_input_chirho)),
        "no transient private review route"
    );
    app_source_manifest_chirho::promote_then_install_reviewed_source_chirho(
        &root_chirho,
        &report_chirho.candidate_chirho.app_chirho,
        &owner_chirho,
        Some(&report_chirho),
        || {
            review_chirho::promote_candidate_with_source_review_report_chirho(
                &root_chirho,
                &report_chirho.candidate_chirho.app_chirho,
                &owner_chirho,
                report_chirho.candidate_chirho.root_dag_chirho.clone(),
                !report_chirho
                    .review_chirho
                    .added_capabilities_chirho
                    .is_empty(),
                report_chirho.review_chirho.cost_delta_token_chirho > 0,
                report_chirho.source_review_report_chirho.clone(),
            )
        },
    )?;
    ensure!(
        report_chirho.candidate_chirho.request_access_policy_chirho
            == Some(cairn_model_app_chirho::AppRequestAccessPolicyChirho::AuthenticatedChirho),
        "authenticated fixture app required"
    );
    let candidate_chirho = blake3::hash(&serde_json::to_vec(&report_chirho.candidate_chirho)?)
        .to_hex()
        .to_string();
    let login_chirho = identity_chirho::login_identity_with_credential_chirho(
        &root_chirho,
        &user_chirho,
        &credential_chirho,
    )?;
    write_session_chirho(
        session_chirho,
        format!(
            "cairn_session_chirho={}:{}\n",
            user_chirho, login_chirho.token_chirho
        )
        .as_bytes(),
    )?;
    owned_chirho.plant_sentinel_chirho()?;
    let latched_chirho = Arc::new(owned_chirho.latch_chirho()?);
    let ports_chirho = ConfiguredLedgerHostRuntimePortsChirho::uncomposed_chirho()
        .with_served_write_relay_chirho(
            Arc::new(authority_chirho::LocalDispatchChirho),
            Arc::new(authority_chirho::ReadDoubleChirho::for_owned_root_chirho(
                Arc::clone(&latched_chirho),
            )),
            ServedWriteRelayDestinationSlotChirho::new_chirho(),
        );
    latched_chirho.begin_runtime_chirho();
    let prepared_chirho = cairn_serve_runtime_chirho::prepare_transient_review_server_chirho(
        &latched_chirho.tenant_chirho(),
        listener_chirho,
        ports_chirho,
    )
    .await?;
    latched_chirho.verify_chirho()?;
    let before_chirho = latched_chirho.snapshot_chirho()?;
    emit_chirho(
        "before-chirho",
        &inputs_chirho,
        &candidate_chirho,
        None,
        Some(&before_chirho),
    )?;
    emit_chirho(
        "ready-chirho",
        &inputs_chirho,
        &candidate_chirho,
        Some(prepared_chirho.local_addr_chirho()?.to_string()),
        None,
    )?;
    let stop_chirho = Arc::new(AtomicBool::new(false));
    let stop_error_chirho = Arc::new(AtomicBool::new(false));
    let watcher_chirho = {
        let stop_chirho = Arc::clone(&stop_chirho);
        let error_chirho = Arc::clone(&stop_error_chirho);
        tokio::spawn(async move {
            while !stop_chirho.load(Ordering::Acquire) {
                match std::fs::symlink_metadata(&args_chirho.stop_chirho) {
                    Ok(meta_chirho) => {
                        if !meta_chirho.is_file() || meta_chirho.file_type().is_symlink() {
                            error_chirho.store(true, Ordering::Release);
                        }
                        stop_chirho.store(true, Ordering::Release);
                    }
                    Err(failure_chirho)
                        if failure_chirho.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_failure_chirho) => {
                        error_chirho.store(true, Ordering::Release);
                        stop_chirho.store(true, Ordering::Release);
                    }
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
    };
    let served_chirho = prepared_chirho
        .serve_until_chirho(Arc::clone(&stop_chirho), Duration::from_secs(30))
        .await;
    stop_chirho.store(true, Ordering::Release);
    watcher_chirho.await?;
    served_chirho?;
    ensure!(
        !stop_error_chirho.load(Ordering::Acquire),
        "stop path unavailable"
    );
    latched_chirho.verify_chirho()?;
    let after_chirho = latched_chirho.snapshot_chirho()?;
    ensure!(before_chirho == after_chirho, "fixture snapshot changed");
    Arc::try_unwrap(latched_chirho)
        .map_err(|_root_chirho| anyhow::anyhow!("fixture custody still retained"))?
        .finish_chirho()?;
    emit_chirho(
        "after-chirho",
        &inputs_chirho,
        &candidate_chirho,
        None,
        Some(&after_chirho),
    )?;
    emit_chirho(
        "stopped-chirho",
        &inputs_chirho,
        &candidate_chirho,
        None,
        None,
    )?;
    Ok(())
}
