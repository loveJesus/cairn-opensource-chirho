// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Binary entry point that seeds ONE test-kind drill root through this crate's injected E-A opener
//! and exits — a one-shot host mutation, never a service.
//!
//! WHY A SECOND BINARY RATHER THAN A FOURTH ARGV ON THE NODE. The serve binary's contract is exactly
//! `<cluster-config.json> <ledger-config.toml> <selected-root>` and 6.5-e's deploy selection depends
//! on that shape; `src/main.rs` already carries special first-argument handling so a version request
//! is not consumed as a config path, which is a sign that contract is load-bearing and fiddly rather
//! than incidental. Seeding and serving also have different lifecycles — seed once before the era,
//! serve for the era's duration — and multiplexing a one-shot MUTATION and a long-running service
//! behind one argv parse is exactly where a mis-parse becomes a mutation. So this target adds a
//! second `[[bin]]` and leaves the serve binary's argv untouched.
//!
//! WHY NAMED FLAGS AND NOT POSITIONALS. Nine required inputs is precisely the "long positional
//! argument list to misorder" that `CreditsDemoSmokeInputsChirho` was made a struct to avoid. Named
//! flags also make the two binaries mutually unmistakable at 2am on a host where they sit side by
//! side: this one refuses a bare positional argument and names the serve binary in the refusal, and
//! the serve binary refuses this one's flag list at its own arity check.
//!
//! ADDS NO DEPENDENCY, for a measured reason. A `serde_json` line on this package (to emit the seed
//! report as JSON) changes the package's `-Cmetadata` and moved the SERVE binary by 64 bytes across
//! 106,070 `nm` lines; the second `[[bin]]` on its own moved it by nothing. So this binary prints the
//! shipping CLI's summary line rather than JSON.
//!
//! NAMES NO DOOR. The widening this binary delivers lives one layer down, in
//! [`cairn_ledger_geo_node_testkind_chirho::run_testkind_credits_demo_geo_seed_chirho`], which
//! injects the E-A opener. This file names neither door, so the provider-door guard's population is
//! unchanged by its existence.

use anyhow::{anyhow, bail, Result};
use cairn_ledger_geo_node_testkind_chirho::run_testkind_credits_demo_geo_seed_chirho;
use cairn_operator_smoke_chirho::credits_demo_smoke_chirho::CreditsDemoSmokeInputsChirho;
use std::ffi::OsString;
use std::path::PathBuf;

/// The serve binary, named IN this binary's usage text on purpose: the two differ only in bytes on a
/// host, so the cheapest way to stop a wrong invocation is for each refusal to name the other.
const SERVE_BIN_CHIRHO: &str = "cairn-ledger-geo-node-testkind-chirho";
const SEED_BIN_CHIRHO: &str = "cairn-ledger-geo-node-testkind-seed-chirho";

const USAGE_CHIRHO: &str = "\
usage: cairn-ledger-geo-node-testkind-seed-chirho \
--root-chirho <selected-root> \
--config-chirho <ledger-config.toml> \
--expected-config-digest-chirho <hex> \
--plan-chirho <regenesis-plan.json> \
--expected-plan-digest-chirho <hex> \
--issuer-secret-name-chirho <secret-ref-name> \
--activation-authorization-chirho <authorization.json> \
--expected-activation-authorization-digest-chirho <hex> \
--payer-credential-secret-name-chirho <secret-ref-name> \
--app-root-chirho <app-source-root> \
[--manifest-chirho <manifest.json>] \
[--reviewed-payer-principal-chirho <user/16-hex>]
  This SEEDS a test-kind drill root once and exits; it does NOT serve.
  --reviewed-payer-principal-chirho registers the plan's payer under exactly that principal, which
  must equal the plan's initial_owner, so roots born from one plan hold one payer (C1 A3).
  To SERVE the test-kind node, run instead:
    cairn-ledger-geo-node-testkind-chirho <cluster-config.json> <ledger-config.toml> <selected-root>";

/// This binary's name PLUS the crate version PLUS the source commit that built these bytes.
///
/// It carries the same weight here as on the serve binary: two test-kind artifacts staged from one
/// tree sit in the same directory, and an operator who cannot ask a staged binary which tree it came
/// from cannot check the deploy-selection invariant.
const VERSION_LINE_CHIRHO: &str =
    cairn_build_identity_chirho::version_line_chirho!("cairn-ledger-geo-node-testkind-seed-chirho");

/// The reviewed operator inputs, one per flag, so no two can be silently transposed.
struct SeedArgsChirho {
    root_chirho: PathBuf,
    config_chirho: PathBuf,
    expected_config_digest_chirho: String,
    plan_chirho: PathBuf,
    expected_plan_digest_chirho: String,
    issuer_secret_name_chirho: String,
    activation_authorization_chirho: PathBuf,
    expected_activation_authorization_digest_chirho: String,
    payer_credential_secret_name_chirho: String,
    app_root_chirho: PathBuf,
    manifest_chirho: Option<PathBuf>,
    reviewed_payer_principal_chirho: Option<String>,
}

/// Store a flag's value exactly once. A repeated flag is a REFUSAL, not a last-one-wins: on a road
/// whose next step is an authoritative mutation, a silently discarded value is the expensive kind of
/// surprise.
fn set_once_chirho(
    slot_chirho: &mut Option<String>,
    flag_chirho: &str,
    value_chirho: String,
) -> Result<()> {
    if slot_chirho.is_some() {
        bail!("{flag_chirho} was supplied more than once\n{USAGE_CHIRHO}");
    }
    *slot_chirho = Some(value_chirho);
    Ok(())
}

fn require_chirho(slot_chirho: Option<String>, flag_chirho: &str) -> Result<String> {
    slot_chirho.ok_or_else(|| anyhow!("{flag_chirho} is required\n{USAGE_CHIRHO}"))
}

fn parse_args_chirho(mut args_chirho: impl Iterator<Item = OsString>) -> Result<SeedArgsChirho> {
    let mut root_chirho = None;
    let mut config_chirho = None;
    let mut expected_config_digest_chirho = None;
    let mut plan_chirho = None;
    let mut expected_plan_digest_chirho = None;
    let mut issuer_secret_name_chirho = None;
    let mut activation_authorization_chirho = None;
    let mut expected_activation_authorization_digest_chirho = None;
    let mut payer_credential_secret_name_chirho = None;
    let mut app_root_chirho = None;
    let mut manifest_chirho = None;
    let mut reviewed_payer_principal_chirho = None;

    while let Some(raw_flag_chirho) = args_chirho.next() {
        let flag_chirho = raw_flag_chirho
            .into_string()
            .map_err(|raw_chirho| anyhow!("argument is not valid UTF-8: {raw_chirho:?}"))?;
        if !flag_chirho.starts_with("--") {
            // THE CROSS-BINARY GUARD. Three bare paths is the SERVE binary's whole contract, so an
            // operator who pastes that line here is told which binary they meant rather than being
            // shown a flag list they must diff against what they typed.
            bail!(
                "{SEED_BIN_CHIRHO} takes named flags, not positional arguments; got {flag_chirho:?}.\n\
                 A bare `<cluster-config.json> <ledger-config.toml> <selected-root>` line belongs to \
                 {SERVE_BIN_CHIRHO}, which SERVES the node.\n{USAGE_CHIRHO}"
            );
        }
        let value_chirho = args_chirho
            .next()
            .ok_or_else(|| anyhow!("{flag_chirho} needs a value\n{USAGE_CHIRHO}"))?
            .into_string()
            .map_err(|raw_chirho| {
                anyhow!("{flag_chirho} value is not valid UTF-8: {raw_chirho:?}")
            })?;
        match flag_chirho.as_str() {
            "--root-chirho" => set_once_chirho(&mut root_chirho, &flag_chirho, value_chirho)?,
            "--config-chirho" => set_once_chirho(&mut config_chirho, &flag_chirho, value_chirho)?,
            "--expected-config-digest-chirho" => set_once_chirho(
                &mut expected_config_digest_chirho,
                &flag_chirho,
                value_chirho,
            )?,
            "--plan-chirho" => set_once_chirho(&mut plan_chirho, &flag_chirho, value_chirho)?,
            "--expected-plan-digest-chirho" => {
                set_once_chirho(&mut expected_plan_digest_chirho, &flag_chirho, value_chirho)?;
            }
            "--issuer-secret-name-chirho" => {
                set_once_chirho(&mut issuer_secret_name_chirho, &flag_chirho, value_chirho)?;
            }
            "--activation-authorization-chirho" => {
                set_once_chirho(
                    &mut activation_authorization_chirho,
                    &flag_chirho,
                    value_chirho,
                )?;
            }
            "--expected-activation-authorization-digest-chirho" => set_once_chirho(
                &mut expected_activation_authorization_digest_chirho,
                &flag_chirho,
                value_chirho,
            )?,
            "--payer-credential-secret-name-chirho" => set_once_chirho(
                &mut payer_credential_secret_name_chirho,
                &flag_chirho,
                value_chirho,
            )?,
            "--app-root-chirho" => {
                set_once_chirho(&mut app_root_chirho, &flag_chirho, value_chirho)?;
            }
            "--manifest-chirho" => {
                set_once_chirho(&mut manifest_chirho, &flag_chirho, value_chirho)?
            }
            "--reviewed-payer-principal-chirho" => set_once_chirho(
                &mut reviewed_payer_principal_chirho,
                &flag_chirho,
                value_chirho,
            )?,
            _ => bail!("unknown flag {flag_chirho}\n{USAGE_CHIRHO}"),
        }
    }

    Ok(SeedArgsChirho {
        root_chirho: PathBuf::from(require_chirho(root_chirho, "--root-chirho")?),
        config_chirho: PathBuf::from(require_chirho(config_chirho, "--config-chirho")?),
        expected_config_digest_chirho: require_chirho(
            expected_config_digest_chirho,
            "--expected-config-digest-chirho",
        )?,
        plan_chirho: PathBuf::from(require_chirho(plan_chirho, "--plan-chirho")?),
        expected_plan_digest_chirho: require_chirho(
            expected_plan_digest_chirho,
            "--expected-plan-digest-chirho",
        )?,
        issuer_secret_name_chirho: require_chirho(
            issuer_secret_name_chirho,
            "--issuer-secret-name-chirho",
        )?,
        activation_authorization_chirho: PathBuf::from(require_chirho(
            activation_authorization_chirho,
            "--activation-authorization-chirho",
        )?),
        expected_activation_authorization_digest_chirho: require_chirho(
            expected_activation_authorization_digest_chirho,
            "--expected-activation-authorization-digest-chirho",
        )?,
        payer_credential_secret_name_chirho: require_chirho(
            payer_credential_secret_name_chirho,
            "--payer-credential-secret-name-chirho",
        )?,
        app_root_chirho: PathBuf::from(require_chirho(app_root_chirho, "--app-root-chirho")?),
        manifest_chirho: manifest_chirho.map(PathBuf::from),
        reviewed_payer_principal_chirho,
    })
}

fn main() -> Result<()> {
    let mut raw_args_chirho = std::env::args_os();
    let _program_chirho = raw_args_chirho.next();
    // BEFORE the flag parse, exactly as the serve binary does it before its positional parse: a
    // version request must never be read as a flag needing a value.
    let first_arg_chirho = raw_args_chirho.next();
    if cairn_build_identity_chirho::is_version_request_chirho(
        first_arg_chirho
            .as_ref()
            .and_then(|arg_chirho| arg_chirho.to_str()),
    ) {
        println!("{VERSION_LINE_CHIRHO}");
        return Ok(());
    }
    let args_chirho = parse_args_chirho(first_arg_chirho.into_iter().chain(raw_args_chirho))?;

    let report_chirho = run_testkind_credits_demo_geo_seed_chirho(&CreditsDemoSmokeInputsChirho {
        root_chirho: &args_chirho.root_chirho,
        config_path_chirho: &args_chirho.config_chirho,
        expected_config_digest_chirho: &args_chirho.expected_config_digest_chirho,
        plan_path_chirho: &args_chirho.plan_chirho,
        expected_plan_digest_chirho: &args_chirho.expected_plan_digest_chirho,
        issuer_secret_name_chirho: &args_chirho.issuer_secret_name_chirho,
        activation_authorization_path_chirho: &args_chirho.activation_authorization_chirho,
        expected_activation_authorization_digest_chirho: &args_chirho
            .expected_activation_authorization_digest_chirho,
        payer_credential_secret_name_chirho: &args_chirho.payer_credential_secret_name_chirho,
        app_root_chirho: &args_chirho.app_root_chirho,
        manifest_path_chirho: args_chirho.manifest_chirho.as_deref(),
        reviewed_payer_principal_chirho: args_chirho.reviewed_payer_principal_chirho.as_deref(),
    })?;
    // THE SHIPPING CLI'S OWN SUMMARY LINE, field for field, plus the two regenesis digests a drill
    // records. Deliberately not JSON: emitting the report as JSON would need `serde_json` as a
    // DIRECT dependency of this package, and that changes the package's `-Cmetadata` — measured to
    // rename every generic instantiation's symbol hash and move the SERVE binary by 64 bytes, which
    // is exactly what this brick's shape exists to avoid. An operator who wants the typed report
    // calls the crate-level consumer; a staged binary prints the line the CLI already prints.
    println!(
        "testkind geo seed={} era={} payer={} plan_mint={} source_review_report={} \
         projection={} projection_head={} regenesis_packet={} regenesis_publication_manifest={} \
         served_money_arc_executed={}",
        report_chirho.geo_seeded_chirho,
        report_chirho.writer_authority_era_chirho,
        report_chirho.payer_chirho,
        report_chirho.plan_mint_amount_chirho,
        report_chirho.source_review_report_chirho,
        report_chirho.projection_name_chirho,
        report_chirho.projection_head_path_chirho,
        report_chirho.regenesis_packet_digest_chirho,
        report_chirho.regenesis_publication_manifest_digest_chirho,
        report_chirho.served_money_arc_executed_chirho,
    );
    Ok(())
}
