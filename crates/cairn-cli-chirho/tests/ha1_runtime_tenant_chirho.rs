// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have everlasting life. - John 3:16 (KJV)

use cairn_chirho::{identity_chirho, tenant_chirho::TenantIdChirho};
use cairn_cli_chirho::args_chirho::{CliChirho, CommandChirho};
use cairn_cli_chirho::cli_context_chirho::CliContextChirho;
use cairn_cli_chirho::dispatch_chirho::run_cli_chirho;
use clap::Parser;
use std::io::Read as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

struct ChildRegistrationServerChirho {
    child_chirho: Option<Child>,
}

impl ChildRegistrationServerChirho {
    fn child_mut_chirho(&mut self) -> &mut Child {
        self.child_chirho.as_mut().expect("child remains available")
    }

    fn stop_chirho(&mut self) {
        if let Some(mut child_chirho) = self.child_chirho.take() {
            let _ = child_chirho.kill();
            let _ = child_chirho.wait();
        }
    }
}

impl Drop for ChildRegistrationServerChirho {
    fn drop(&mut self) {
        self.stop_chirho();
    }
}

fn temp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-ha1-{label_chirho}-{}-{n_chirho}",
        std::process::id()
    ))
}

fn config_digest_chirho(config_path_chirho: &std::path::Path) -> String {
    let config_bytes_chirho = std::fs::read(config_path_chirho).unwrap();
    cairn_ledger_regenesis_chirho::ledger_host_config_digest_chirho(&config_bytes_chirho)
}

fn assert_platform_root_refusal_chirho(error_chirho: anyhow::Error, command_chirho: &str) {
    let text_chirho = error_chirho.to_string();
    assert!(
        text_chirho.contains(&format!(
            "cairn-chirho {command_chirho} would serve PlatformRootChirho"
        )),
        "unexpected error: {text_chirho}"
    );
    assert!(
        text_chirho.contains("--tenant <tenant-id>")
            && text_chirho.contains("--allow-platform-root-chirho"),
        "platform-root refusal must name the tenant path and explicit operator override: {text_chirho}"
    );
}

#[test]
fn serve_requires_tenant_or_explicit_platform_root_override_chirho() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let root_chirho = temp_root_chirho("serve-root");
            let root_arg_chirho = root_chirho.display().to_string();
            let cli_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                root_arg_chirho.as_str(),
                "serve",
                "--port",
                "0",
            ])
            .unwrap();
            assert_platform_root_refusal_chirho(
                run_cli_chirho(cli_chirho).expect_err("implicit platform-root serve should fail"),
                "serve",
            );
            let parsed_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                root_arg_chirho.as_str(),
                "serve",
                "--port",
                "0",
                "--allow-platform-root-chirho",
            ])
            .unwrap();
            match parsed_chirho.command_chirho {
                CommandChirho::ServeChirho(args_chirho) => {
                    assert!(args_chirho.allow_platform_root_chirho)
                }
                other_chirho => panic!(
                    "expected serve command, got {:?}",
                    std::mem::discriminant(&other_chirho)
                ),
            }
            let _ = std::fs::remove_dir_all(root_chirho);
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn up_requires_tenant_or_explicit_platform_root_override_chirho() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let root_chirho = temp_root_chirho("up-root");
            std::fs::create_dir_all(&root_chirho).unwrap();
            let config_chirho = root_chirho.join("cairn-chirho.toml");
            std::fs::write(
                &config_chirho,
                format!(
                    "root_chirho = {:?}\nport_chirho = 0\n",
                    root_chirho.display().to_string()
                ),
            )
            .unwrap();
            let config_arg_chirho = config_chirho.display().to_string();
            let expected_config_digest_chirho = config_digest_chirho(&config_chirho);
            let cli_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "up",
                "--config",
                config_arg_chirho.as_str(),
                "--expected-config-digest-chirho",
                expected_config_digest_chirho.as_str(),
            ])
            .unwrap();
            assert_platform_root_refusal_chirho(
                run_cli_chirho(cli_chirho).expect_err("implicit platform-root up should fail"),
                "up",
            );
            let parsed_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "up",
                "--config",
                config_arg_chirho.as_str(),
                "--expected-config-digest-chirho",
                expected_config_digest_chirho.as_str(),
                "--allow-platform-root-chirho",
            ])
            .unwrap();
            match parsed_chirho.command_chirho {
                CommandChirho::UpChirho(args_chirho) => {
                    assert!(args_chirho.allow_platform_root_chirho)
                }
                other_chirho => panic!(
                    "expected up command, got {:?}",
                    std::mem::discriminant(&other_chirho)
                ),
            }
            let _ = std::fs::remove_dir_all(root_chirho);
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn up_refuses_invalid_ledger_host_before_listener_or_storage_write_chirho() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let root_chirho = temp_root_chirho("up-invalid-ledger-host");
            std::fs::create_dir_all(&root_chirho).unwrap();
            let listener_chirho = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port_chirho = listener_chirho.local_addr().unwrap().port();
            let config_path_chirho = root_chirho.join("cairn-chirho.toml");
            std::fs::write(
                &config_path_chirho,
                format!(
                    r#"root_chirho = {:?}
port_chirho = {port_chirho}
[ledger_host_chirho]
schema_chirho = "ledger-host-config-v1-chirho"
storage_namespace_chirho = "missing-ledger-storage-chirho"
monitor_evidence_namespace_chirho = "missing-monitor-storage-chirho"
monitor_evidence_path_chirho = "cycles/conservation-chirho.jsonl"
money_group_id_chirho = "credits-money-group-chirho"
cluster_id_chirho = "credits-cluster-chirho"
journal_path_chirho = "journals/credits-chirho.jsonl"
local_epoch_chirho = 1
kind_registry_path_chirho = "registries/kinds-chirho.jsonl"
kind_registry_id_chirho = "credits-kinds-chirho"
projection_registry_path_chirho = "registries/projections-chirho.jsonl"
projection_registry_id_chirho = "credits-projections-chirho"
source_registry_path_chirho = "registries/sources-chirho.jsonl"
source_registry_id_chirho = "credits-sources-chirho"
monitor_cadence_ms_chirho = 5000
[[ledger_host_chirho.members_chirho]]
owner_chirho = "credits-user-chirho"
kind_id_chirho = "credits-chirho"
[ledger_host_chirho.kind_issuer_chirho]
principal_chirho = "platform-issuer-chirho"
verifying_key_hex_chirho = "{}"
[[ledger_host_chirho.projection_routes_chirho]]
projection_name_chirho = "credits-balances-chirho"
head_path_chirho = "projections/credits-balances-chirho"
[ledger_host_chirho.signer_secrets_chirho]
journal_chirho = "ledger-journal-key-chirho"
config_chirho = "ledger-config-key-chirho"
feeder_chirho = "ledger-feeder-key-chirho"
kind_root_chirho = "ledger-kind-root-key-chirho"
effect_intent_chirho = "effect-intent-key-chirho"
effect_terminal_chirho = "effect-terminal-key-chirho"
"#,
                    root_chirho.display().to_string(),
                    "11".repeat(32),
                ),
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    &config_path_chirho,
                    std::fs::Permissions::from_mode(0o600),
                )
                .unwrap();
            }
            let before_chirho = std::fs::read(&config_path_chirho).unwrap();
            let config_arg_chirho = config_path_chirho.display().to_string();
            let expected_config_digest_chirho = config_digest_chirho(&config_path_chirho);
            let cli_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "up",
                "--config",
                config_arg_chirho.as_str(),
                "--expected-config-digest-chirho",
                expected_config_digest_chirho.as_str(),
                "--allow-platform-root-chirho",
            ])
            .unwrap();
            let error_chirho = run_cli_chirho(cli_chirho)
                .expect_err("an unprovisioned strict ledger host must fail before listen");
            let error_text_chirho = error_chirho.to_string();
            assert!(
                error_text_chirho.contains("ledger storage namespace is unavailable"),
                "unexpected startup refusal: {error_text_chirho}"
            );
            assert!(!error_text_chirho.contains("Address already in use"));
            assert_eq!(std::fs::read(&config_path_chirho).unwrap(), before_chirho);
            assert!(!root_chirho.join("missing-ledger-storage-chirho").exists());
            assert!(!root_chirho.join("missing-monitor-storage-chirho").exists());
            drop(listener_chirho);
            let _ = std::fs::remove_dir_all(root_chirho);
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn explicit_tenant_serve_still_resolves_tenant_root_chirho() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let root_chirho = temp_root_chirho("serve-tenant");
            let root_arg_chirho = root_chirho.display().to_string();
            let cli_chirho = CliChirho::try_parse_from([
                "cairn-chirho",
                "--root",
                root_arg_chirho.as_str(),
                "--tenant",
                "tenant-a-chirho",
                "serve",
                "--port",
                "0",
            ])
            .unwrap();
            let context_chirho = CliContextChirho::from_cli_chirho(&cli_chirho).unwrap();
            assert_eq!(
                context_chirho.tenant_chirho(),
                &TenantIdChirho::TenantChirho("tenant-a-chirho".to_string())
            );
            assert!(context_chirho
                .root_chirho()
                .ends_with("tenants-chirho/tenant-a-chirho"));
            assert!(context_chirho
                .root_chirho()
                .join("tenant-chirho.json")
                .is_file());
            let _ = std::fs::remove_dir_all(root_chirho);
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn up_threads_registration_token_to_public_handler_chirho() {
    let root_chirho = temp_root_chirho("up-registration-token");
    std::fs::create_dir_all(&root_chirho).unwrap();
    let registration_token_chirho = "up-registration-token-secret-chirho";
    let port_chirho = {
        let listener_chirho = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener_chirho.local_addr().unwrap().port()
    };
    let config_path_chirho = root_chirho.join("cairn-chirho.toml");
    std::fs::write(
        &config_path_chirho,
        format!(
            "root_chirho = {:?}\nport_chirho = {port_chirho}\nregistration_token_chirho = {:?}\n",
            root_chirho.display().to_string(),
            registration_token_chirho,
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config_path_chirho, std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }

    let expected_config_digest_chirho = config_digest_chirho(&config_path_chirho);

    let mut server_chirho = ChildRegistrationServerChirho {
        child_chirho: Some(
            Command::new(env!("CARGO_BIN_EXE_cairn-chirho"))
                .args([
                    "up",
                    "--config",
                    config_path_chirho.to_str().unwrap(),
                    "--expected-config-digest-chirho",
                    expected_config_digest_chirho.as_str(),
                    "--allow-platform-root-chirho",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        ),
    };
    let base_url_chirho = format!("http://127.0.0.1:{port_chirho}");
    let agent_chirho = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(2))
        .build();
    let mut healthy_chirho = false;
    let health_deadline_chirho = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status_chirho) = server_chirho.child_mut_chirho().try_wait().unwrap() {
            let mut stderr_chirho = String::new();
            if let Some(stderr_pipe_chirho) = server_chirho.child_mut_chirho().stderr.as_mut() {
                stderr_pipe_chirho
                    .read_to_string(&mut stderr_chirho)
                    .unwrap();
            }
            panic!("cairn up exited {status_chirho}: {stderr_chirho}");
        }
        if agent_chirho
            .get(&format!("{base_url_chirho}/healthz-chirho"))
            .call()
            .is_ok()
        {
            healthy_chirho = true;
            break;
        }
        if Instant::now() >= health_deadline_chirho {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(healthy_chirho, "cairn up did not become healthy");

    let challenge_chirho: serde_json::Value = agent_chirho
        .get(&format!("{base_url_chirho}/auth-chirho/human-check-chirho"))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    let challenge_token_chirho = challenge_chirho["human_check_token_chirho"]
        .as_str()
        .unwrap();
    let answer_chirho = (0..=40)
        .map(|answer_chirho| answer_chirho.to_string())
        .find(|answer_chirho| {
            identity_chirho::verify_auth_human_check_chirho(
                &root_chirho,
                challenge_token_chirho,
                answer_chirho,
            )
            .is_ok()
        })
        .unwrap();
    let response_chirho = agent_chirho
        .post(&format!("{base_url_chirho}/auth-chirho/register-chirho"))
        .send_json(serde_json::json!({
            "kind_chirho": "user",
            "credential_chirho": "up-threaded-credential-secret-chirho",
            "registration_token_chirho": registration_token_chirho,
            "human_check_chirho": answer_chirho,
            "human_check_token_chirho": challenge_token_chirho,
        }))
        .unwrap();
    assert_eq!(response_chirho.status(), 200);

    server_chirho.stop_chirho();
    assert_eq!(
        identity_chirho::verify_identities_chirho(&root_chirho).unwrap(),
        1
    );
    assert_eq!(
        identity_chirho::verify_auth_attempts_chirho(&root_chirho).unwrap(),
        1
    );
    assert!(identity_chirho::load_sessions_chirho(&root_chirho)
        .unwrap()
        .is_empty());
    assert!(
        cairn_chirho::legacy_ledger_evidence_chirho::load_entries_chirho(&root_chirho)
            .unwrap()
            .is_empty()
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}
