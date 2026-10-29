// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Domain, DNS, and mailbox CLI command handlers.

use crate::args_chirho::CommandChirho;
use crate::parse_helpers_chirho::parse_dns_record_spec_chirho;
use cairn_chirho::{
    dns_apply_chirho, dns_zone_chirho, domain_binding_chirho, hosting_status_chirho,
    mailbox_apply_chirho, mailbox_chirho,
};
use std::path::Path;

pub(crate) fn handle_domain_command_chirho(
    root_chirho: &Path,
    command_chirho: &CommandChirho,
) -> anyhow::Result<bool> {
    match command_chirho {
        CommandChirho::DnsApplyStubChirho(args_chirho) => {
            let crate::args_chirho::domain_args_chirho::DnsApplyStubArgsChirho {
                owner_chirho,
                domain_chirho,
                idempotency_key_chirho,
            } = args_chirho;
            let record_chirho = dns_apply_chirho::emit_dns_apply_stub_chirho(
                root_chirho,
                owner_chirho,
                domain_chirho,
                idempotency_key_chirho,
            )?;
            println!(
                "dns apply (stub, no network) recorded for {domain_chirho}: {} record(s) from zone seq {} (apply #{})",
                record_chirho.zone_record_count_chirho,
                record_chirho.applied_zone_seq_chirho,
                record_chirho.seq_chirho
            );
            Ok(true)
        }
        CommandChirho::MailboxApplyStubChirho(args_chirho) => {
            let crate::args_chirho::domain_args_chirho::MailboxApplyStubArgsChirho {
                owner_chirho,
                domain_chirho,
                idempotency_key_chirho,
            } = args_chirho;
            let record_chirho = mailbox_apply_chirho::emit_mailbox_apply_stub_chirho(
                root_chirho,
                owner_chirho,
                domain_chirho,
                idempotency_key_chirho,
            )?;
            println!(
                "mailbox apply (stub, no network) recorded for {domain_chirho}: {} live mailbox(es) (apply #{})",
                record_chirho.live_mailbox_count_chirho, record_chirho.seq_chirho
            );
            Ok(true)
        }
        CommandChirho::MailboxAppliesChirho(args_chirho) => {
            let crate::args_chirho::domain_args_chirho::MailboxAppliesArgsChirho { json_chirho } =
                args_chirho;
            let records_chirho =
                mailbox_apply_chirho::verified_mailbox_apply_records_chirho(root_chirho)?;
            if *json_chirho {
                println!("{}", serde_json::to_string_pretty(&records_chirho)?);
            } else if records_chirho.is_empty() {
                println!("(no mailbox applies)");
            } else {
                for record_chirho in &records_chirho {
                    println!(
                        "#{} {} {} mailbox(es) via {}",
                        record_chirho.seq_chirho,
                        record_chirho.domain_chirho,
                        record_chirho.live_mailbox_count_chirho,
                        record_chirho.provider_label_chirho
                    );
                }
            }
            Ok(true)
        }
        CommandChirho::DnsAppliesChirho(args_chirho) => {
            let crate::args_chirho::domain_args_chirho::DnsAppliesArgsChirho { json_chirho } =
                args_chirho;
            let records_chirho = dns_apply_chirho::verified_dns_apply_records_chirho(root_chirho)?;
            if *json_chirho {
                println!("{}", serde_json::to_string_pretty(&records_chirho)?);
            } else if records_chirho.is_empty() {
                println!("(no dns applies)");
            } else {
                for record_chirho in &records_chirho {
                    println!(
                        "#{} {} {} record(s) via {}",
                        record_chirho.seq_chirho,
                        record_chirho.domain_chirho,
                        record_chirho.zone_record_count_chirho,
                        record_chirho.provider_label_chirho
                    );
                }
            }
            Ok(true)
        }
        CommandChirho::DomainStatusChirho(args_chirho) => {
            let crate::args_chirho::domain_args_chirho::DomainStatusArgsChirho {
                domain_chirho,
                json_chirho,
            } = args_chirho;
            let status_chirho =
                hosting_status_chirho::hosting_status_chirho(root_chirho, domain_chirho)?;
            if *json_chirho {
                println!("{}", serde_json::to_string_pretty(&status_chirho)?);
            } else {
                println!(
                    "{}: routed={} ({} live binding(s)), dns_zone={} ({} record(s): {})",
                    status_chirho.domain_chirho,
                    status_chirho.routed_chirho,
                    status_chirho.live_binding_count_chirho,
                    status_chirho.has_dns_zone_chirho,
                    status_chirho.dns_record_count_chirho,
                    status_chirho.dns_record_types_chirho.join(", ")
                );
                for binding_chirho in &status_chirho.bindings_chirho {
                    println!(
                        "  {}{} -> {}",
                        binding_chirho.host_chirho,
                        binding_chirho.path_prefix_chirho,
                        binding_chirho.app_chirho
                    );
                }
            }
            Ok(true)
        }
        CommandChirho::MailboxSetChirho(args_chirho) => {
            let crate::args_chirho::domain_args_chirho::MailboxSetArgsChirho {
                owner_chirho,
                domain_chirho,
                local_part_chirho,
                kind_chirho,
                target_chirho,
            } = args_chirho;
            let kind_val_chirho = match kind_chirho.as_str() {
                "mailbox" => mailbox_chirho::MailboxKindChirho::MailboxChirho,
                "alias" => mailbox_chirho::MailboxKindChirho::AliasChirho,
                other_chirho => {
                    anyhow::bail!("unknown mailbox kind '{other_chirho}' (use mailbox|alias)")
                }
            };
            let record_chirho = mailbox_chirho::emit_mailbox_chirho(
                root_chirho,
                mailbox_chirho::MailboxInputChirho {
                    owner_principal_chirho: owner_chirho.to_string(),
                    domain_chirho: domain_chirho.to_string(),
                    local_part_chirho: local_part_chirho.to_string(),
                    kind_chirho: kind_val_chirho,
                    alias_target_chirho: target_chirho.as_ref().cloned(),
                    status_chirho: mailbox_chirho::MailboxStatusChirho::ActiveChirho,
                },
            )?;
            println!(
                "mailbox set on {domain_chirho} (record #{}, address sealed in a private blob)",
                record_chirho.seq_chirho
            );
            Ok(true)
        }
        CommandChirho::MailboxRemoveChirho(args_chirho) => {
            let crate::args_chirho::domain_args_chirho::MailboxRemoveArgsChirho {
                owner_chirho,
                domain_chirho,
                local_part_chirho,
            } = args_chirho;
            let record_chirho = mailbox_chirho::emit_mailbox_chirho(
                root_chirho,
                mailbox_chirho::MailboxInputChirho {
                    owner_principal_chirho: owner_chirho.to_string(),
                    domain_chirho: domain_chirho.to_string(),
                    local_part_chirho: local_part_chirho.to_string(),
                    kind_chirho: mailbox_chirho::MailboxKindChirho::MailboxChirho,
                    alias_target_chirho: None,
                    status_chirho: mailbox_chirho::MailboxStatusChirho::RemovedChirho,
                },
            )?;
            println!(
                "mailbox removed on {domain_chirho} (record #{})",
                record_chirho.seq_chirho
            );
            Ok(true)
        }
        CommandChirho::MailboxesChirho(args_chirho) => {
            let crate::args_chirho::domain_args_chirho::MailboxesArgsChirho {
                owner_chirho,
                json_chirho,
            } = args_chirho;
            let rows_chirho =
                mailbox_chirho::mailbox_safe_rows_for_owner_chirho(root_chirho, owner_chirho)?;
            if *json_chirho {
                println!("{}", serde_json::to_string_pretty(&rows_chirho)?);
            } else if rows_chirho.is_empty() {
                println!("(no mailboxes)");
            } else {
                for row_chirho in &rows_chirho {
                    println!(
                        "#{} {} {:?} {:?} live={} hash={}",
                        row_chirho.seq_chirho,
                        row_chirho.domain_chirho,
                        row_chirho.kind_chirho,
                        row_chirho.status_chirho,
                        row_chirho.live_chirho,
                        &row_chirho.local_part_hash_chirho[..12]
                    );
                }
            }
            Ok(true)
        }
        CommandChirho::DnsZoneSetChirho(args_chirho) => {
            let crate::args_chirho::domain_args_chirho::DnsZoneSetArgsChirho {
                owner_chirho,
                domain_chirho,
                records_chirho,
            } = args_chirho;
            let mut parsed_chirho = Vec::new();
            for spec_chirho in records_chirho {
                parsed_chirho.push(parse_dns_record_spec_chirho(spec_chirho)?);
            }
            let record_chirho = dns_zone_chirho::emit_dns_zone_chirho(
                root_chirho,
                dns_zone_chirho::DnsZoneInputChirho {
                    owner_principal_chirho: owner_chirho.to_string(),
                    domain_chirho: domain_chirho.to_string(),
                    records_chirho: parsed_chirho,
                },
            )?;
            println!(
                "dns zone set for {domain_chirho}: {} record(s) (zone #{})",
                record_chirho.records_chirho.len(),
                record_chirho.seq_chirho
            );
            Ok(true)
        }
        CommandChirho::DnsZonesChirho(args_chirho) => {
            let crate::args_chirho::domain_args_chirho::DnsZonesArgsChirho { json_chirho } =
                args_chirho;
            let records_chirho = dns_zone_chirho::verified_dns_zone_records_chirho(root_chirho)?;
            if *json_chirho {
                println!("{}", serde_json::to_string_pretty(&records_chirho)?);
            } else if records_chirho.is_empty() {
                println!("(no dns zones)");
            } else {
                for record_chirho in &records_chirho {
                    println!(
                        "#{} {} ({} record(s))",
                        record_chirho.seq_chirho,
                        record_chirho.domain_chirho,
                        record_chirho.records_chirho.len()
                    );
                }
            }
            Ok(true)
        }
        CommandChirho::DomainBindingsChirho(args_chirho) => {
            let crate::args_chirho::domain_args_chirho::DomainBindingsArgsChirho { json_chirho } =
                args_chirho;
            let records_chirho =
                domain_binding_chirho::verified_domain_bindings_chirho(root_chirho)?;
            if *json_chirho {
                println!("{}", serde_json::to_string_pretty(&records_chirho)?);
            } else if records_chirho.is_empty() {
                println!("(no domain bindings)");
            } else {
                for record_chirho in &records_chirho {
                    let route_chirho = record_chirho
                        .route_base_chirho
                        .as_deref()
                        .map(|r_chirho| format!("/{r_chirho}"))
                        .unwrap_or_default();
                    println!(
                        "#{} {:?} {}{} -> {}{}",
                        record_chirho.seq_chirho,
                        record_chirho.status_chirho,
                        record_chirho.host_chirho,
                        record_chirho.path_prefix_chirho,
                        record_chirho.app_chirho,
                        route_chirho
                    );
                }
            }
            Ok(true)
        }
        CommandChirho::DomainBindChirho(args_chirho) => {
            let crate::args_chirho::domain_args_chirho::DomainBindArgsChirho {
                owner_chirho,
                host_chirho,
                path_chirho,
                app_chirho,
                route_chirho,
            } = args_chirho;
            let record_chirho = domain_binding_chirho::emit_domain_binding_chirho(
                root_chirho,
                domain_binding_chirho::DomainBindingInputChirho {
                    owner_principal_chirho: owner_chirho.to_string(),
                    host_chirho: host_chirho.to_string(),
                    path_prefix_chirho: path_chirho.to_string(),
                    app_chirho: app_chirho.to_string(),
                    route_base_chirho: route_chirho.as_ref().cloned(),
                    status_chirho: domain_binding_chirho::DomainBindingStatusChirho::ActiveChirho,
                },
            )?;
            println!(
                "bound {host_chirho}{path_chirho} -> {app_chirho} (binding #{})",
                record_chirho.seq_chirho
            );
            Ok(true)
        }
        CommandChirho::DomainUnbindChirho(args_chirho) => {
            let crate::args_chirho::domain_args_chirho::DomainUnbindArgsChirho {
                owner_chirho,
                host_chirho,
                path_chirho,
                app_chirho,
            } = args_chirho;
            let record_chirho = domain_binding_chirho::emit_domain_binding_chirho(
                root_chirho,
                domain_binding_chirho::DomainBindingInputChirho {
                    owner_principal_chirho: owner_chirho.to_string(),
                    host_chirho: host_chirho.to_string(),
                    path_prefix_chirho: path_chirho.to_string(),
                    app_chirho: app_chirho.to_string(),
                    route_base_chirho: None,
                    status_chirho: domain_binding_chirho::DomainBindingStatusChirho::RemovedChirho,
                },
            )?;
            println!(
                "unbound {host_chirho}{path_chirho} (binding #{})",
                record_chirho.seq_chirho
            );
            Ok(true)
        }
        _ => Ok(false),
    }
}
