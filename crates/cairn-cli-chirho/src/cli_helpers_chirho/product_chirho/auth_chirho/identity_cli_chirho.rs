// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have everlasting life. - John 3:16

//! Identity, wallet, and OAuth CLI helpers split out of dispatch_chirho.rs.

use crate::args_chirho::CommandChirho;
use crate::credential_cli_chirho::{
    read_cli_private_credential_file_chirho, resolve_cli_optional_credential_chirho,
    resolve_cli_required_credential_chirho,
};
use anyhow::Context;
use cairn_chirho::{identity_chirho, oauth_chirho};
use cairn_status_command_chirho::print_identity_credential_inventory_chirho;
use std::path::Path;

pub(crate) fn handle_identity_command_chirho(
    root_chirho: &Path,
    command_chirho: CommandChirho,
) -> anyhow::Result<Option<CommandChirho>> {
    match command_chirho {
        CommandChirho::IdentityRegisterChirho(args_chirho) => {
            let crate::args_chirho::auth_args_chirho::IdentityRegisterArgsChirho {
                kind_chirho,
                credential_chirho,
                credential_file_chirho,
            } = args_chirho;
            let kind_chirho = identity_chirho::PrincipalKindChirho::parse_chirho(&kind_chirho)?;
            let credential_chirho =
                resolve_cli_optional_credential_chirho(credential_chirho, credential_file_chirho)?;
            let identity_chirho = match credential_chirho {
                Some(credential_chirho) => {
                    identity_chirho::register_identity_with_credential_chirho(
                        root_chirho,
                        kind_chirho,
                        &credential_chirho,
                    )?
                }
                None => identity_chirho::register_identity_chirho(root_chirho, kind_chirho)?,
            };
            println!(
                "{}\twallet={}\tpubkey={}",
                identity_chirho.principal_chirho,
                identity_chirho.wallet_chirho,
                &identity_chirho.pubkey_chirho[..identity_chirho.pubkey_chirho.len().min(16)]
            );
            Ok(None)
        }
        CommandChirho::IdentityListChirho => {
            let mut identities_chirho = identity_chirho::load_identities_chirho(root_chirho)?;
            identities_chirho.sort_by_key(|record_chirho| record_chirho.seq_chirho);
            if identities_chirho.is_empty() {
                println!("(no identities)");
            }
            for record_chirho in &identities_chirho {
                println!(
                    "{}\t{:?}\twallet={}\tpubkey={}",
                    record_chirho.principal_chirho,
                    record_chirho.kind_chirho,
                    record_chirho.wallet_chirho,
                    &record_chirho.pubkey_chirho[..record_chirho.pubkey_chirho.len().min(16)]
                );
            }
            Ok(None)
        }
        CommandChirho::IdentityCredentialInventoryChirho(args_chirho) => {
            let crate::args_chirho::auth_args_chirho::IdentityCredentialInventoryArgsChirho {
                json_chirho,
                fail_on_legacy_chirho,
            } = args_chirho;
            let inventory_chirho = identity_chirho::credential_inventory_chirho(root_chirho)?;
            if json_chirho {
                println!("{}", serde_json::to_string_pretty(&inventory_chirho)?);
            } else {
                print_identity_credential_inventory_chirho(&inventory_chirho);
            }
            if fail_on_legacy_chirho && !inventory_chirho.legacy_rotation_ready_chirho {
                anyhow::bail!(
                    "identity credential inventory is not launch-ready: legacy={} invalid={} missing={} extra={} invalid_recovery_codes={}",
                    inventory_chirho.legacy_blake3_credentials_chirho,
                    inventory_chirho.invalid_key_files_chirho,
                    inventory_chirho.missing_key_files_chirho,
                    inventory_chirho.extra_key_files_chirho,
                    inventory_chirho.invalid_recovery_codes_chirho
                );
            }
            Ok(None)
        }
        CommandChirho::IdentityCredentialSetChirho(args_chirho) => {
            let crate::args_chirho::auth_args_chirho::IdentityCredentialSetArgsChirho {
                principal_chirho,
                credential_file_chirho,
            } = args_chirho;
            let credential_chirho =
                read_cli_private_credential_file_chirho(&credential_file_chirho)?;
            identity_chirho::set_identity_credential_chirho(
                root_chirho,
                &principal_chirho,
                &credential_chirho,
            )?;
            println!(
                "credential_set principal_hash={} credential_value_recorded=false credential_file_path_recorded=false raw_principal_recorded=false",
                identity_chirho::identity_inventory_principal_hash_chirho(&principal_chirho)
            );
            Ok(None)
        }
        CommandChirho::IdentityCredentialResetChirho(args_chirho) => {
            let crate::args_chirho::auth_args_chirho::IdentityCredentialResetArgsChirho {
                principal_chirho,
                credential_file_chirho,
                reason_chirho,
            } = args_chirho;
            let credential_chirho =
                read_cli_private_credential_file_chirho(&credential_file_chirho)?;
            let report_chirho = identity_chirho::reset_identity_credential_chirho(
                root_chirho,
                &principal_chirho,
                &credential_chirho,
                "operator-cli-chirho",
                &reason_chirho,
            )?;
            // Hashes and counts only: no principal, no value, no path, no stored hash.
            println!(
                "credential_reset principal_hash={} reset_seq={} revoked_sessions={} credential_value_recorded=false credential_file_path_recorded=false raw_principal_recorded=false",
                identity_chirho::identity_inventory_principal_hash_chirho(&principal_chirho),
                report_chirho.record_chirho.seq_chirho,
                report_chirho.record_chirho.revoked_session_count_chirho
            );
            Ok(None)
        }
        CommandChirho::IdentityInviteChirho(args_chirho) => {
            let crate::args_chirho::auth_args_chirho::IdentityInviteArgsChirho {
                kind_chirho,
                json_chirho,
            } = args_chirho;
            let kind_chirho = identity_chirho::PrincipalKindChirho::parse_chirho(&kind_chirho)?;
            let issued_chirho = identity_chirho::invite_identity_chirho(root_chirho, kind_chirho)?;
            print_issued_recovery_code_chirho(&issued_chirho, json_chirho)?;
            Ok(None)
        }
        CommandChirho::IdentityRecoveryCodeMintChirho(args_chirho) => {
            let crate::args_chirho::auth_args_chirho::IdentityRecoveryCodeMintArgsChirho {
                principal_chirho,
                json_chirho,
            } = args_chirho;
            let issued_chirho = identity_chirho::mint_operator_recovery_code_chirho(
                root_chirho,
                &principal_chirho,
            )?;
            print_issued_recovery_code_chirho(&issued_chirho, json_chirho)?;
            Ok(None)
        }
        CommandChirho::IdentityRecoveryCodeEventsChirho(args_chirho) => {
            let crate::args_chirho::auth_args_chirho::IdentityRecoveryCodeEventsArgsChirho {
                json_chirho,
            } = args_chirho;
            let rows_chirho =
                identity_chirho::load_recovery_code_events_for_display_chirho(root_chirho)?;
            print_recovery_code_events_chirho(&rows_chirho, json_chirho)?;
            Ok(None)
        }
        CommandChirho::IdentityRecoveryCodeEventsVerifyChirho => {
            let count_chirho = identity_chirho::verify_recovery_code_events_chirho(root_chirho)?;
            println!("verified {count_chirho} identity recovery code events");
            Ok(None)
        }
        CommandChirho::IdentityLoginChirho { principal_chirho } => {
            let login_chirho =
                identity_chirho::login_identity_chirho(root_chirho, &principal_chirho)?;
            println!(
                "principal={}\ttoken={}\texpires_ms={}",
                login_chirho.session_chirho.principal_chirho,
                login_chirho.token_chirho,
                login_chirho.session_chirho.expires_ms_chirho
            );
            Ok(None)
        }
        CommandChirho::IdentitySessionsListChirho { principal_chirho } => {
            let rows_chirho =
                identity_chirho::list_principal_sessions_chirho(root_chirho, &principal_chirho)?;
            if rows_chirho.is_empty() {
                println!("(no sessions)");
            }
            for row_chirho in &rows_chirho {
                println!(
                    "seq={}\tissued_ms={}\texpires_ms={}\tstate={}",
                    row_chirho.seq_chirho,
                    row_chirho.issued_ms_chirho,
                    row_chirho.expires_ms_chirho,
                    row_chirho.state_chirho.label_chirho()
                );
            }
            Ok(None)
        }
        CommandChirho::IdentitySessionRevokeChirho(args_chirho) => {
            let crate::args_chirho::auth_args_chirho::IdentitySessionRevokeArgsChirho {
                principal_chirho,
                token_file_chirho,
                session_seq_chirho,
                reason_chirho,
            } = args_chirho;
            let record_chirho = match (token_file_chirho, session_seq_chirho) {
                (Some(token_file_chirho), None) => {
                    let token_chirho = std::fs::read_to_string(&token_file_chirho)
                        .with_context(|| format!("read {}", token_file_chirho.display()))?;
                    identity_chirho::revoke_session_token_chirho(
                        root_chirho,
                        &principal_chirho,
                        token_chirho.trim_end_matches(['\r', '\n']),
                        "operator-cli-chirho",
                        &reason_chirho,
                    )?
                }
                (None, Some(session_seq_chirho)) => identity_chirho::revoke_session_by_seq_chirho(
                    root_chirho,
                    &principal_chirho,
                    session_seq_chirho,
                    "operator-cli-chirho",
                    &reason_chirho,
                )?,
                (Some(_), Some(_)) => {
                    anyhow::bail!("use exactly one of --token-file or --session-seq")
                }
                (None, None) => anyhow::bail!("use exactly one of --token-file or --session-seq"),
            };
            println!(
                "revoked identity session principal_hash={} session_seq={} token_hash={} revocation_seq={}",
                identity_chirho::identity_inventory_principal_hash_chirho(
                    &record_chirho.principal_chirho
                ),
                record_chirho.session_seq_chirho,
                record_chirho.token_hash_chirho,
                record_chirho.seq_chirho
            );
            Ok(None)
        }
        CommandChirho::IdentityVerifyChirho => {
            let count_chirho = identity_chirho::verify_identities_chirho(root_chirho)?;
            println!("verified {count_chirho} identity record(s)");
            Ok(None)
        }
        CommandChirho::IdentitySessionsVerifyChirho => {
            let count_chirho = identity_chirho::verify_sessions_chirho(root_chirho)?;
            println!("verified {count_chirho} identity session(s)");
            Ok(None)
        }
        CommandChirho::IdentitySessionRevocationsVerifyChirho => {
            let count_chirho = identity_chirho::verify_session_revocations_chirho(root_chirho)?;
            println!("verified {count_chirho} identity session revocation(s)");
            Ok(None)
        }
        CommandChirho::IdentityCredentialResetsVerifyChirho => {
            let count_chirho = identity_chirho::verify_credential_resets_chirho(root_chirho)?;
            println!("verified {count_chirho} identity credential reset(s)");
            Ok(None)
        }
        CommandChirho::OauthClientRegisterChirho(args_chirho) => {
            let crate::args_chirho::auth_args_chirho::OauthClientRegisterArgsChirho {
                app_chirho,
                owner_chirho,
            } = args_chirho;
            let client_chirho =
                oauth_chirho::register_client_chirho(root_chirho, &app_chirho, &owner_chirho)?;
            println!(
                "{}\tapp={}\towner={}",
                client_chirho.client_id_chirho,
                client_chirho.app_chirho,
                client_chirho.owner_principal_chirho
            );
            Ok(None)
        }
        CommandChirho::OauthClientsChirho => {
            let mut clients_chirho = oauth_chirho::load_clients_chirho(root_chirho)?;
            clients_chirho.sort_by_key(|record_chirho| record_chirho.seq_chirho);
            if clients_chirho.is_empty() {
                println!("(no oauth clients)");
            }
            for client_chirho in &clients_chirho {
                println!(
                    "{}\tapp={}\towner={}",
                    client_chirho.client_id_chirho,
                    client_chirho.app_chirho,
                    client_chirho.owner_principal_chirho
                );
            }
            Ok(None)
        }
        CommandChirho::OauthTokenChirho(args_chirho) => {
            let crate::args_chirho::auth_args_chirho::OauthTokenArgsChirho {
                principal_chirho,
                credential_chirho,
                credential_file_chirho,
                client_chirho,
                scopes_chirho,
                rate_window_ms_chirho,
                rate_max_invokes_chirho,
                device_id_chirho,
            } = args_chirho;
            let rate_limit_chirho = match (rate_window_ms_chirho, rate_max_invokes_chirho) {
                (Some(window_ms_chirho), Some(max_invokes_chirho)) => {
                    Some(oauth_chirho::ScopedTokenRateLimitChirho {
                        window_ms_chirho,
                        max_invokes_chirho,
                        device_id_chirho,
                    })
                }
                (None, None) => {
                    if device_id_chirho.is_some() {
                        anyhow::bail!(
                            "--device-id requires --rate-window-ms and --rate-max-invokes"
                        );
                    }
                    None
                }
                _ => anyhow::bail!(
                    "--rate-window-ms and --rate-max-invokes must be provided together"
                ),
            };
            let credential_chirho =
                resolve_cli_required_credential_chirho(credential_chirho, credential_file_chirho)?;
            let token_chirho = oauth_chirho::issue_scoped_token_with_rate_limit_chirho(
                root_chirho,
                &principal_chirho,
                &credential_chirho,
                &client_chirho,
                scopes_chirho,
                rate_limit_chirho,
            )?;
            println!(
                "principal={}\tclient={}\tapp={}\ttoken={}\texpires_ms={}",
                token_chirho.record_chirho.principal_chirho,
                token_chirho.record_chirho.client_id_chirho,
                token_chirho.record_chirho.app_chirho,
                token_chirho.token_chirho,
                token_chirho.record_chirho.expires_ms_chirho
            );
            if let Some(rate_limit_chirho) = &token_chirho.record_chirho.rate_limit_chirho {
                println!(
                    "  rate_limit window_ms={} max_invokes={} device_id={}",
                    rate_limit_chirho.window_ms_chirho,
                    rate_limit_chirho.max_invokes_chirho,
                    rate_limit_chirho
                        .device_id_chirho
                        .as_deref()
                        .unwrap_or("(none)")
                );
            }
            Ok(None)
        }
        CommandChirho::OauthLimitedKeyChirho(args_chirho) => {
            let crate::args_chirho::auth_args_chirho::OauthLimitedKeyArgsChirho {
                principal_chirho,
                credential_chirho,
                credential_file_chirho,
                client_chirho,
                actions_chirho,
                rate_window_ms_chirho,
                rate_max_invokes_chirho,
            } = args_chirho;
            let rate_limit_chirho = match (rate_window_ms_chirho, rate_max_invokes_chirho) {
                (Some(window_ms_chirho), Some(max_invokes_chirho)) => {
                    Some(oauth_chirho::ScopedTokenRateLimitChirho {
                        window_ms_chirho,
                        max_invokes_chirho,
                        device_id_chirho: None,
                    })
                }
                (None, None) => None,
                _ => anyhow::bail!(
                    "--rate-window-ms and --rate-max-invokes must be provided together"
                ),
            };
            let credential_chirho =
                resolve_cli_required_credential_chirho(credential_chirho, credential_file_chirho)?;
            let key_chirho = oauth_chirho::issue_limited_key_chirho(
                root_chirho,
                &principal_chirho,
                &credential_chirho,
                &client_chirho,
                &actions_chirho,
                rate_limit_chirho,
            )?;
            let granted_chirho = key_chirho
                .record_chirho
                .limited_grants_chirho
                .as_ref()
                .map(|grants_chirho| {
                    grants_chirho
                        .actions_chirho
                        .iter()
                        .map(|grant_chirho| grant_chirho.action_chirho.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default();
            println!(
                "principal={}\tclient={}\tapp={}\ttoken={}\texpires_ms={}\tactions={}",
                key_chirho.record_chirho.principal_chirho,
                key_chirho.record_chirho.client_id_chirho,
                key_chirho.record_chirho.app_chirho,
                key_chirho.token_chirho,
                key_chirho.record_chirho.expires_ms_chirho,
                granted_chirho
            );
            Ok(None)
        }
        CommandChirho::OauthUsesChirho => {
            let records_chirho = oauth_chirho::load_scoped_token_uses_chirho(root_chirho)?;
            if records_chirho.is_empty() {
                println!("(no scoped token uses)");
            }
            for record_chirho in records_chirho {
                println!(
                    "#{}\ttoken=#{}\tprincipal={}\tclient={}\tapp={}\tdevice={}\twindow_ms={}\tmax={}",
                    record_chirho.seq_chirho,
                    record_chirho.scoped_token_seq_chirho,
                    record_chirho.principal_chirho,
                    record_chirho.client_id_chirho,
                    record_chirho.app_chirho,
                    record_chirho.device_id_chirho.as_deref().unwrap_or("(none)"),
                    record_chirho.window_ms_chirho,
                    record_chirho.max_invokes_chirho
                );
            }
            Ok(None)
        }
        CommandChirho::OauthVerifyChirho => {
            let clients_chirho = oauth_chirho::verify_clients_chirho(root_chirho)?;
            let tokens_chirho = oauth_chirho::verify_scoped_tokens_chirho(root_chirho)?;
            let uses_chirho = oauth_chirho::verify_scoped_token_uses_chirho(root_chirho)?;
            // K4: the connection stores verify too, so a fault there fails this command. Their counts print only from
            // `oauth-connection-verify`: this line's exact shape is what the recut host scripts parse
            // (`deploy-chirho/cax11-artifacts-chirho/hosted-evidence-chirho/r15-recut-chirho/r15_host_chirho.sh`).
            oauth_chirho::verify_connection_clients_chirho(root_chirho)?;
            oauth_chirho::verify_connection_token_uses_chirho(root_chirho)?;
            println!(
                "verified {clients_chirho} oauth client(s), {tokens_chirho} scoped token(s), {uses_chirho} scoped token use(s)"
            );
            Ok(None)
        }
        CommandChirho::OauthConnectionVerifyChirho => {
            let clients_chirho = oauth_chirho::verify_connection_clients_chirho(root_chirho)?;
            let keys_chirho = oauth_chirho::verify_connection_tokens_chirho(root_chirho)?;
            let uses_chirho = oauth_chirho::verify_connection_token_uses_chirho(root_chirho)?;
            println!(
                "verified {clients_chirho} connection client(s), {keys_chirho} connection key(s), {uses_chirho} \
                 connection key use(s)"
            );
            Ok(None)
        }
        other_chirho => Ok(Some(other_chirho)),
    }
}

/// The code prints ONCE, here, on stdout, and nowhere else: never a log, never stderr. With `--json`, exactly the three
/// fields PFE's send tool reads (PFE #26035, item 3), so the operator can redirect it into an owner-only file.
fn print_issued_recovery_code_chirho(
    issued_chirho: &identity_chirho::IssuedRecoveryCodeChirho,
    json_chirho: bool,
) -> anyhow::Result<()> {
    if json_chirho {
        println!("{}", serde_json::to_string(issued_chirho)?);
    } else {
        println!(
            "{}\trecovery_code={}\texpires_ms={}",
            issued_chirho.principal_chirho,
            issued_chirho.recovery_code_chirho,
            issued_chirho.expires_ms_chirho
        );
    }
    Ok(())
}

/// Every row with its VALID or INVALID label. Principals print as hashes and actors as a class, never raw, so a
/// listing is shareable as evidence.
fn print_recovery_code_events_chirho(
    rows_chirho: &[identity_chirho::RecoveryCodeEventDisplayRowChirho],
    json_chirho: bool,
) -> anyhow::Result<()> {
    let mut out_chirho = Vec::new();
    for row_chirho in rows_chirho {
        let Some(event_chirho) = row_chirho.record_chirho.as_ref() else {
            out_chirho.push(serde_json::json!({
                "line_chirho": row_chirho.line_chirho,
                "valid_chirho": false,
                "error_chirho": row_chirho.validation_error_chirho,
            }));
            continue;
        };
        let actor_class_chirho =
            if event_chirho.actor_chirho == identity_chirho::RECOVERY_CODE_OPERATOR_ACTOR_CHIRHO {
                identity_chirho::RECOVERY_CODE_OPERATOR_ACTOR_CHIRHO
            } else if event_chirho.actor_chirho == event_chirho.principal_chirho {
                "principal-chirho"
            } else {
                "other-chirho"
            };
        out_chirho.push(serde_json::json!({
            "line_chirho": row_chirho.line_chirho,
            "valid_chirho": row_chirho.valid_chirho(),
            "error_chirho": row_chirho.validation_error_chirho,
            "seq_chirho": event_chirho.seq_chirho,
            "principal_hash_chirho": identity_chirho::identity_inventory_principal_hash_chirho(
                &event_chirho.principal_chirho
            ),
            "kind_chirho": event_chirho.kind_chirho,
            "reason_kind_chirho": event_chirho.reason_kind_chirho,
            "actor_class_chirho": actor_class_chirho,
            "code_state_digest_chirho": event_chirho.code_state_digest_chirho,
            "expires_ms_chirho": event_chirho.expires_ms_chirho,
            "credential_generation_chirho": event_chirho.credential_generation_chirho,
            "at_ms_chirho": event_chirho.at_ms_chirho,
        }));
    }
    if json_chirho {
        println!("{}", serde_json::to_string_pretty(&out_chirho)?);
        return Ok(());
    }
    if out_chirho.is_empty() {
        println!("(no recovery code events)");
    }
    for row_chirho in &out_chirho {
        let label_chirho = if row_chirho["valid_chirho"] == true {
            "VALID"
        } else {
            "INVALID"
        };
        let text_chirho = |key_chirho: &str| match &row_chirho[key_chirho] {
            serde_json::Value::String(value_chirho) => value_chirho.clone(),
            serde_json::Value::Null => "-".to_string(),
            other_chirho => other_chirho.to_string(),
        };
        println!(
            "line {}\t{label_chirho}\tseq={}\tprincipal_hash={}\t{}\t{}\tactor={}\tgeneration={}\texpires_ms={}\terror={}",
            text_chirho("line_chirho"),
            text_chirho("seq_chirho"),
            text_chirho("principal_hash_chirho"),
            text_chirho("kind_chirho"),
            text_chirho("reason_kind_chirho"),
            text_chirho("actor_class_chirho"),
            text_chirho("credential_generation_chirho"),
            text_chirho("expires_ms_chirho"),
            text_chirho("error_chirho"),
        );
    }
    Ok(())
}

#[cfg(test)]
#[path = "oauth_verify_cli_tests_chirho.rs"]
mod oauth_verify_cli_tests_chirho;
