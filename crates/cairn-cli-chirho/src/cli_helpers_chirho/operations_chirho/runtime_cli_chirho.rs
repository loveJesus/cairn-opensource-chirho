// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use crate::args_chirho::CommandChirho;
use cairn_chirho::model_chirho::CapabilityChirho;
use cairn_chirho::{cas_chirho, config_chirho, effect_chirho, store_chirho, tenant_chirho};
use cairn_serve_runtime_chirho as serve_chirho;
use std::path::{Path, PathBuf};
use std::sync::Arc;

// Public-registration branch: spec-chirho/workflows-chirho/identity-auth-chirho/public-registration-gate-chirho.md
pub(crate) fn handle_runtime_command_chirho(
    root_chirho: &Path,
    cli_tenant_chirho: &tenant_chirho::TenantIdChirho,
    command_chirho: CommandChirho,
) -> anyhow::Result<Option<CommandChirho>> {
    match command_chirho {
        CommandChirho::ServeChirho(args_chirho) => {
            let crate::args_chirho::ops_args_chirho::ServeArgsChirho {
                port_chirho,
                registration_token_chirho,
                allow_platform_root_chirho,
                sign_in_principal_successes_per_hour_chirho,
                sign_in_source_successes_per_hour_chirho,
                sign_in_source_failures_per_window_chirho,
            } = args_chirho;
            require_runtime_platform_root_override_chirho(
                cli_tenant_chirho,
                allow_platform_root_chirho,
                "serve",
            )?;
            let runtime_chirho = tokio::runtime::Runtime::new()?;
            runtime_chirho.block_on(
                serve_chirho::serve_with_registration_token_and_limits_chirho(
                    root_chirho,
                    port_chirho,
                    32,
                    String::new(),
                    registration_token_chirho,
                    serve_limits_chirho(
                        sign_in_principal_successes_per_hour_chirho,
                        sign_in_source_successes_per_hour_chirho,
                        sign_in_source_failures_per_window_chirho,
                    ),
                ),
            )?;
            Ok(None)
        }
        CommandChirho::UpChirho(args_chirho) => {
            let crate::args_chirho::ops_args_chirho::UpArgsChirho {
                config_path_chirho,
                expected_config_digest_chirho,
                allow_platform_root_chirho,
            } = args_chirho;
            let config_file_chirho =
                config_path_chirho.unwrap_or_else(|| PathBuf::from("cairn-chirho.toml"));
            let cfg_chirho = config_chirho::load_digest_bound_config_chirho(
                &config_file_chirho,
                &expected_config_digest_chirho,
            )?;
            let up_tenant_chirho = tenant_chirho::tenant_id_with_fallback_chirho(
                cli_tenant_chirho,
                cfg_chirho.tenant_chirho.as_deref(),
            )?;
            require_runtime_platform_root_override_chirho(
                &up_tenant_chirho,
                allow_platform_root_chirho,
                "up",
            )?;
            let serve_root_chirho = tenant_chirho::root_for_tenant_chirho(
                std::path::Path::new(&cfg_chirho.root_chirho),
                &up_tenant_chirho,
            )?;
            if let Some(cluster_config_chirho) = cfg_chirho.geo_cluster_config_chirho.as_deref() {
                let cluster_config_chirho =
                    resolve_sibling_config_path_chirho(&config_file_chirho, cluster_config_chirho);
                cairn_ledger_geo_node_chirho::serve_resident_gd7_voter_geo_node_chirho(
                    &cluster_config_chirho,
                    &config_file_chirho,
                    &expected_config_digest_chirho,
                    &serve_root_chirho,
                )?;
                return Ok(None);
            }
            let ledger_runtime_ports_chirho =
                if let Some(ledger_host_config_chirho) = cfg_chirho.ledger_host_chirho.as_ref() {
                    let host_chirho = std::sync::Arc::new(
                        serve_chirho::LedgerHostProjectionReadPortChirho::open_existing_chirho(
                            &serve_root_chirho,
                            &config_file_chirho,
                            ledger_host_config_chirho,
                        )?,
                    );
                    let postgres_effect_chirho = ledger_host_config_chirho
                        .postgres_effect_chirho
                        .as_ref()
                        .map(|_postgres_config_chirho| {
                            serve_chirho::open_shared_ledger_host_postgres_effect_runtime_chirho(
                                &serve_root_chirho,
                                &config_file_chirho,
                                host_chirho.clone(),
                                ledger_host_config_chirho,
                            )
                        })
                        .transpose()?;
                    serve_chirho::ConfiguredLedgerHostRuntimePortsChirho::composed_chirho(
                        host_chirho,
                        postgres_effect_chirho,
                    )
                } else {
                    serve_chirho::ConfiguredLedgerHostRuntimePortsChirho::uncomposed_chirho()
                };
            println!(
                "cairn-chirho up: root={} tenant={} port={} inflight={} domain_routing={} (config {})",
                cfg_chirho.root_chirho,
                up_tenant_chirho,
                cfg_chirho.port_chirho,
                cfg_chirho.inflight_limit_chirho,
                cfg_chirho.domain_routing_enabled_chirho,
                config_file_chirho.display()
            );
            let runtime_chirho = tokio::runtime::Runtime::new()?;
            let served_request_limits_chirho = serve_chirho::ServedRequestAbuseLimitsChirho {
                window_ms_chirho: cfg_chirho.served_request_window_ms_chirho,
                actor_max_requests_chirho: cfg_chirho.served_request_actor_max_chirho,
                actor_max_body_bytes_chirho: cfg_chirho.served_request_actor_body_bytes_chirho,
                global_max_requests_chirho: cfg_chirho.served_request_global_max_chirho,
                global_max_body_bytes_chirho: cfg_chirho.served_request_global_body_bytes_chirho,
                actor_bucket_cap_chirho: cfg_chirho.served_request_actor_bucket_cap_chirho,
                sign_in_principal_successes_per_hour_chirho: cfg_chirho
                    .sign_in_principal_successes_per_hour_chirho,
                sign_in_source_successes_per_hour_chirho: cfg_chirho
                    .sign_in_source_successes_per_hour_chirho,
                sign_in_source_failures_per_window_chirho: cfg_chirho
                    .sign_in_source_failures_per_window_chirho,
            };
            runtime_chirho.block_on(serve_chirho::serve_with_configured_ledger_host_chirho(
                &serve_root_chirho,
                cfg_chirho.port_chirho,
                cfg_chirho.inflight_limit_chirho,
                serve_chirho::ServeAuthTokensChirho::new_chirho(
                    cfg_chirho.publish_token_chirho.clone(),
                    cfg_chirho.registration_token_chirho.clone(),
                )
                .with_connection_issuance_enabled_chirho(
                    cfg_chirho.connection_issuance_enabled_chirho,
                ),
                cfg_chirho.domain_routing_enabled_chirho,
                served_request_limits_chirho,
                ledger_runtime_ports_chirho,
            ))?;
            Ok(None)
        }
        CommandChirho::LedgerCompensationPreviewChirho(args_chirho) => {
            let runtime_chirho = open_ledger_runtime_chirho(
                root_chirho,
                &args_chirho.config_path_chirho,
                &args_chirho.expected_config_digest_chirho,
            )?;
            let report_chirho =
                serve_chirho::preview_current_ledger_host_postgres_compensation_chirho(
                    &runtime_chirho,
                    root_chirho,
                    &args_chirho.app_chirho,
                    &args_chirho.owner_chirho,
                )?;
            println!("{}", serde_json::to_string(&report_chirho)?);
            Ok(None)
        }
        CommandChirho::LedgerRuntimePreflightChirho(args_chirho) => {
            preflight_ledger_runtime_chirho(
                root_chirho,
                &args_chirho.config_path_chirho,
                &args_chirho.expected_config_digest_chirho,
            )?;
            println!("ledger_runtime_chirho=ready-chirho");
            Ok(None)
        }
        CommandChirho::LedgerCompensationExecuteChirho(args_chirho) => {
            let runtime_chirho = open_ledger_runtime_chirho(
                root_chirho,
                &args_chirho.config_path_chirho,
                &args_chirho.expected_config_digest_chirho,
            )?;
            let report_chirho =
                serve_chirho::execute_current_ledger_host_postgres_compensation_chirho(
                    &runtime_chirho,
                    root_chirho,
                    &args_chirho.app_chirho,
                    &args_chirho.owner_chirho,
                )?;
            println!("{}", serde_json::to_string(&report_chirho)?);
            Ok(None)
        }
        CommandChirho::QueryEffectChirho(args_chirho) => {
            let crate::args_chirho::state_args_chirho::QueryEffectArgsChirho {
                caller_chirho,
                prefix_chirho,
                request_prefix_chirho,
                limit_chirho,
                max_rows_chirho,
            } = args_chirho;
            let request_chirho = effect_chirho::ScopedQueryRequestChirho {
                prefix_chirho: request_prefix_chirho,
                limit_chirho,
            };
            let request_bytes_chirho = serde_json::to_vec(&request_chirho)?;
            let idem_chirho = store_chirho::hash_object_chirho(&(
                "query-effect-chirho",
                &caller_chirho,
                &prefix_chirho,
                &request_chirho,
            ))?;
            let effect_chirho = effect_chirho::run_effect_chirho(
                root_chirho,
                0,
                idem_chirho,
                CapabilityChirho::QueryChirho {
                    prefix_chirho,
                    caller_chirho,
                    max_rows_chirho,
                },
                &request_bytes_chirho,
            )?;
            let response_hash_chirho = effect_chirho
                .response_chirho
                .ok_or_else(|| anyhow::anyhow!("query effect produced no response"))?;
            let response_bytes_chirho = cas_chirho::get_chirho(root_chirho, &response_hash_chirho)?;
            let response_chirho: effect_chirho::ScopedQueryResponseChirho =
                serde_json::from_slice(&response_bytes_chirho)?;
            for row_chirho in &response_chirho.rows_chirho {
                println!(
                    "{}\t{}\t{}",
                    row_chirho.key_chirho, row_chirho.value_chirho, row_chirho.value_len_chirho
                );
            }
            println!(
                "({} rows, ledger seq {})",
                response_chirho.row_count_chirho, response_chirho.ledger_seq_chirho
            );
            Ok(None)
        }
        other_chirho => Ok(Some(other_chirho)),
    }
}

fn open_ledger_runtime_chirho(
    root_chirho: &Path,
    config_path_chirho: &Path,
    expected_config_digest_chirho: &str,
) -> anyhow::Result<serve_chirho::SharedLedgerHostPostgresEffectRuntimeChirho> {
    let (config_chirho, host_chirho) = load_and_open_ledger_host_chirho(
        root_chirho,
        config_path_chirho,
        expected_config_digest_chirho,
    )?;
    let ledger_config_chirho = config_chirho
        .ledger_host_chirho
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("ledger runtime needs verified ledger-host config"))?;
    serve_chirho::open_shared_ledger_host_postgres_effect_runtime_chirho(
        root_chirho,
        config_path_chirho,
        Arc::new(host_chirho),
        ledger_config_chirho,
    )
}

/// The one place the runtime openers resolve a verified ledger-host config and its projection read
/// port, so the compensation opener and the read-only preflight cannot diverge on which config or
/// which host they are talking about.
fn load_and_open_ledger_host_chirho(
    root_chirho: &Path,
    config_path_chirho: &Path,
    expected_config_digest_chirho: &str,
) -> anyhow::Result<(
    config_chirho::ConfigChirho,
    serve_chirho::LedgerHostProjectionReadPortChirho,
)> {
    let config_chirho = config_chirho::load_digest_bound_config_chirho(
        config_path_chirho,
        expected_config_digest_chirho,
    )?;
    let ledger_config_chirho = config_chirho
        .ledger_host_chirho
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("ledger runtime needs verified ledger-host config"))?;
    let _postgres_config_chirho = ledger_config_chirho
        .postgres_effect_chirho
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("ledger runtime needs LocalPhaseB PostgreSQL config"))?;
    let host_chirho = serve_chirho::LedgerHostProjectionReadPortChirho::open_existing_chirho(
        root_chirho,
        config_path_chirho,
        ledger_config_chirho,
    )?;
    Ok((config_chirho, host_chirho))
}

/// Resolve the same verified ledger-host config and projection read port the runtime opener uses,
/// then run the served effect runtime's own preconditions and drop them.
///
/// It shares `load_and_open_ledger_host_chirho` with the compensation opener, so the config and
/// projection-host resolution cannot drift; what it does NOT do is open a resident effect journal,
/// because a read-only preflight must not take the money-authority door to answer a read question.
fn preflight_ledger_runtime_chirho(
    root_chirho: &Path,
    config_path_chirho: &Path,
    expected_config_digest_chirho: &str,
) -> anyhow::Result<()> {
    let (config_chirho, host_chirho) = load_and_open_ledger_host_chirho(
        root_chirho,
        config_path_chirho,
        expected_config_digest_chirho,
    )?;
    let ledger_config_chirho = config_chirho
        .ledger_host_chirho
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("ledger runtime needs verified ledger-host config"))?;
    serve_chirho::preflight_ledger_host_postgres_effect_runtime_chirho(
        root_chirho,
        &host_chirho,
        ledger_config_chirho,
    )
}

fn resolve_sibling_config_path_chirho(config_path_chirho: &Path, value_chirho: &str) -> PathBuf {
    let value_chirho = PathBuf::from(value_chirho);
    if value_chirho.is_absolute() {
        value_chirho
    } else {
        config_path_chirho
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(value_chirho)
    }
}

fn require_runtime_platform_root_override_chirho(
    tenant_chirho: &tenant_chirho::TenantIdChirho,
    allow_platform_root_chirho: bool,
    command_chirho: &str,
) -> anyhow::Result<()> {
    if tenant_chirho.is_platform_root_chirho() && !allow_platform_root_chirho {
        anyhow::bail!(
            "cairn-chirho {command_chirho} would serve PlatformRootChirho; pass --tenant <tenant-id> for customer roots or --allow-platform-root-chirho for explicit operator platform-root serving"
        );
    }
    Ok(())
}

/// The `serve` road's served-request limits: the defaults, with the sign-in rates and the per-source failure limit from
/// its flags when given (brick 4a; PFE #25942; R12). The stand-in and part 10 raise them; production keeps `up` and its
/// reviewed TOML.
fn serve_limits_chirho(
    principal_successes_per_hour_chirho: Option<u64>,
    source_successes_per_hour_chirho: Option<u64>,
    source_failures_per_window_chirho: Option<u64>,
) -> serve_chirho::ServedRequestAbuseLimitsChirho {
    let defaults_chirho = serve_chirho::ServedRequestAbuseLimitsChirho::default();
    serve_chirho::ServedRequestAbuseLimitsChirho {
        sign_in_principal_successes_per_hour_chirho: principal_successes_per_hour_chirho
            .unwrap_or(defaults_chirho.sign_in_principal_successes_per_hour_chirho),
        sign_in_source_successes_per_hour_chirho: source_successes_per_hour_chirho
            .unwrap_or(defaults_chirho.sign_in_source_successes_per_hour_chirho),
        sign_in_source_failures_per_window_chirho: source_failures_per_window_chirho
            .unwrap_or(defaults_chirho.sign_in_source_failures_per_window_chirho),
        ..defaults_chirho
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::args_chirho::ops_args_chirho::UpArgsChirho;

    fn directory_entries_chirho(root_chirho: &Path) -> Vec<String> {
        let mut entries_chirho = std::fs::read_dir(root_chirho)
            .unwrap()
            .map(|entry_chirho| {
                entry_chirho
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        entries_chirho.sort();
        entries_chirho
    }

    #[test]
    fn up_refuses_a_same_owner_root_repoint_before_either_root_is_touched_chirho() {
        let nonce_chirho = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_chirho = std::env::temp_dir().join(format!(
            "cairn-up-config-repoint-{}-{nonce_chirho}-chirho",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_chirho);
        std::fs::create_dir(&temp_chirho).unwrap();
        let reviewed_root_chirho = temp_chirho.join("reviewed-root-chirho");
        let repointed_root_chirho = temp_chirho.join("repointed-root-chirho");
        std::fs::create_dir(&reviewed_root_chirho).unwrap();
        std::fs::create_dir(&repointed_root_chirho).unwrap();
        std::fs::write(
            reviewed_root_chirho.join("sentinel-chirho"),
            b"reviewed-chirho",
        )
        .unwrap();
        std::fs::write(
            repointed_root_chirho.join("sentinel-chirho"),
            b"repointed-chirho",
        )
        .unwrap();
        let config_path_chirho = temp_chirho.join("host-config-chirho.toml");
        let reviewed_config_chirho = format!(
            "root_chirho = {:?}\ntenant_chirho = \"tenant-a-chirho\"\n",
            reviewed_root_chirho.display().to_string()
        );
        std::fs::write(&config_path_chirho, reviewed_config_chirho.as_bytes()).unwrap();
        let expected_config_digest_chirho =
            cairn_chirho::cas_chirho::hash_chirho(reviewed_config_chirho.as_bytes()).0;
        let repointed_config_chirho = format!(
            "root_chirho = {:?}\ntenant_chirho = \"tenant-a-chirho\"\n",
            repointed_root_chirho.display().to_string()
        );
        std::fs::write(&config_path_chirho, repointed_config_chirho).unwrap();
        let reviewed_entries_chirho = directory_entries_chirho(&reviewed_root_chirho);
        let repointed_entries_chirho = directory_entries_chirho(&repointed_root_chirho);

        let refusal_chirho = match handle_runtime_command_chirho(
            &reviewed_root_chirho,
            &tenant_chirho::TenantIdChirho::TenantChirho("tenant-a-chirho".to_owned()),
            CommandChirho::UpChirho(UpArgsChirho {
                config_path_chirho: Some(config_path_chirho),
                expected_config_digest_chirho,
                allow_platform_root_chirho: false,
            }),
        ) {
            Err(refusal_chirho) => refusal_chirho,
            Ok(_) => panic!("the edited config unexpectedly reached runtime startup"),
        };

        assert!(
            format!("{refusal_chirho:#}").contains("LedgerHostConfigDigestMismatchChirho"),
            "the edited bytes must refuse at the external digest identity: {refusal_chirho:#}"
        );
        assert_eq!(
            directory_entries_chirho(&reviewed_root_chirho),
            reviewed_entries_chirho
        );
        assert_eq!(
            directory_entries_chirho(&repointed_root_chirho),
            repointed_entries_chirho
        );
        std::fs::remove_dir_all(temp_chirho).unwrap();
    }

    /// `serve`'s sign-in flags set exactly the two sign-in rates and leave every other limit at its default; without
    /// them the defaults stand (PFE #25942).
    #[test]
    fn serve_flags_set_only_the_sign_in_rates_chirho() {
        let defaults_chirho = serve_chirho::ServedRequestAbuseLimitsChirho::default();
        let unset_chirho = serve_limits_chirho(None, None, None);
        assert_eq!(
            unset_chirho.sign_in_principal_successes_per_hour_chirho,
            defaults_chirho.sign_in_principal_successes_per_hour_chirho
        );
        assert_eq!(
            unset_chirho.sign_in_source_successes_per_hour_chirho,
            defaults_chirho.sign_in_source_successes_per_hour_chirho
        );
        assert_eq!(
            unset_chirho.sign_in_source_failures_per_window_chirho,
            defaults_chirho.sign_in_source_failures_per_window_chirho
        );
        let raised_chirho = serve_limits_chirho(Some(10_000), Some(20_000), Some(30_000));
        assert_eq!(
            raised_chirho.sign_in_principal_successes_per_hour_chirho,
            10_000
        );
        assert_eq!(
            raised_chirho.sign_in_source_successes_per_hour_chirho,
            20_000
        );
        assert_eq!(
            raised_chirho.sign_in_source_failures_per_window_chirho,
            30_000
        );
        assert_eq!(
            raised_chirho.window_ms_chirho,
            defaults_chirho.window_ms_chirho
        );
        assert_eq!(
            raised_chirho.actor_max_requests_chirho,
            defaults_chirho.actor_max_requests_chirho
        );
        assert_eq!(
            raised_chirho.actor_bucket_cap_chirho,
            defaults_chirho.actor_bucket_cap_chirho
        );
        let parsed_chirho = <crate::args_chirho::CliChirho as clap::Parser>::try_parse_from([
            "cairn-chirho",
            "serve",
            "--sign-in-principal-successes-per-hour-chirho",
            "7000",
            "--sign-in-source-successes-per-hour-chirho",
            "9000",
            "--sign-in-source-failures-per-window-chirho",
            "11000",
        ]);
        assert!(
            parsed_chirho.is_ok(),
            "serve accepts the three sign-in flags"
        );
    }

    /// The host TOML's sign-in defaults and the identity crate's are ONE policy written twice (the root crate takes the
    /// config crate only behind a feature, so neither can import the other's). Equal, or a host without the keys gets a
    /// different limit than the code documents (brick 4a; PFE #25922).
    #[test]
    fn the_config_sign_in_defaults_are_the_identity_defaults_chirho() {
        let config_chirho = config_chirho::ConfigChirho::default();
        assert_eq!(
            config_chirho.sign_in_principal_successes_per_hour_chirho,
            cairn_chirho::identity_chirho::SIGN_IN_PRINCIPAL_SUCCESSES_PER_HOUR_DEFAULT_CHIRHO
        );
        assert_eq!(
            config_chirho.sign_in_source_successes_per_hour_chirho,
            cairn_chirho::identity_chirho::SIGN_IN_SOURCE_SUCCESSES_PER_HOUR_DEFAULT_CHIRHO
        );
        assert_eq!(
            config_chirho.sign_in_source_failures_per_window_chirho,
            cairn_chirho::identity_chirho::SIGN_IN_SOURCE_FAILURES_PER_WINDOW_DEFAULT_CHIRHO
        );
    }
}
