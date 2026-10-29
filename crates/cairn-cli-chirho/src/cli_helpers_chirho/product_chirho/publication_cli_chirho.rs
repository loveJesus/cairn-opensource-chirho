// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Publication CLI: the platform applier (`publication-apply`, the timer's command), the
//! operator's slug reservation, and a verifier over every publication log on a root.

use crate::args_chirho::CommandChirho;
use cairn_chirho::publication_chirho::{self, apply_chirho};
use clap::Args;
use std::path::Path;

#[derive(Clone, Debug, Args)]
pub struct PublicationApplyArgsChirho {
    /// The prepared tenant whose intents this PLATFORM root applies. Deliberately not the global
    /// `--tenant`, which re-scopes the root itself into that tenant; the applier must run on the
    /// platform root and refuses a tenant root by construction.
    #[arg(long = "for-tenant")]
    pub for_tenant_chirho: String,
    #[arg(long = "json")]
    pub json_chirho: bool,
}

#[derive(Clone, Debug, Args)]
pub struct PublicationReserveSlugArgsChirho {
    #[arg(long = "slug")]
    pub slug_chirho: String,
    /// A closed vocabulary (`platform-app-chirho`, `workspace-app-chirho`, `template-name-chirho`,
    /// `operator-policy-chirho`); the reasoning behind a reservation stays outside the log.
    #[arg(long = "reason", value_parser = parse_reserved_slug_reason_chirho)]
    pub reason_kind_chirho: apply_chirho::ReservedSlugReasonChirho,
}

fn parse_reserved_slug_reason_chirho(
    text_chirho: &str,
) -> Result<apply_chirho::ReservedSlugReasonChirho, String> {
    text_chirho
        .parse()
        .map_err(|error_chirho: anyhow::Error| error_chirho.to_string())
}

pub fn handle_publication_command_chirho(
    root_chirho: &Path,
    command_chirho: &CommandChirho,
) -> anyhow::Result<bool> {
    match command_chirho {
        CommandChirho::PublicationApplyChirho(args_chirho) => {
            let report_chirho = apply_chirho::apply_publication_intents_chirho(
                root_chirho,
                &args_chirho.for_tenant_chirho,
            )?;
            if args_chirho.json_chirho {
                println!("{}", serde_json::to_string(&report_chirho)?);
            } else {
                println!(
                    "publication-apply tenant={} seen={} already_applied={} applied={} refused={}",
                    report_chirho.tenant_chirho,
                    report_chirho.intents_seen_chirho,
                    report_chirho.already_applied_chirho,
                    report_chirho.applied_chirho,
                    report_chirho.refused_chirho
                );
                for (code_chirho, count_chirho) in &report_chirho.refusals_chirho {
                    println!("  refused {code_chirho}: {count_chirho}");
                }
            }
            Ok(true)
        }
        CommandChirho::PublicationReserveSlugChirho(args_chirho) => {
            let record_chirho = apply_chirho::reserve_publication_slug_chirho(
                root_chirho,
                &args_chirho.slug_chirho,
                args_chirho.reason_kind_chirho,
            )?;
            println!(
                "publication slug reserved '{}' seq={} reason={}",
                record_chirho.slug_chirho,
                record_chirho.seq_chirho,
                record_chirho.reason_kind_chirho.label_chirho()
            );
            Ok(true)
        }
        CommandChirho::PublicationVerifyChirho => {
            let intents_chirho =
                publication_chirho::verify_publication_intents_chirho(root_chirho)?;
            let applied_chirho =
                publication_chirho::verify_publication_applied_chirho(root_chirho)?;
            let owners_chirho = apply_chirho::verify_publication_owners_chirho(root_chirho)?;
            let claims_chirho = apply_chirho::verify_slug_claims_chirho(root_chirho)?;
            let reserved_chirho = apply_chirho::verify_reserved_slugs_chirho(root_chirho)?;
            println!(
                "publication verify intents={intents_chirho} applied={applied_chirho} owners={owners_chirho} claims={claims_chirho} reserved={reserved_chirho}"
            );
            Ok(true)
        }
        _ => Ok(false),
    }
}
