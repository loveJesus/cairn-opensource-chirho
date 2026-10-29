// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Dev-only: serve the composed served-LLM card on one test-kind root over loopback, with the stub
//! provider, until a stop file appears, printing the verified substrate balances before and after.
//!
//! WHY AN EXAMPLE IN THIS CRATE. The card needs a resident handle opened through the test-kind door,
//! and the door guards forbid every shipping binary from naming it
//! (`open_resident_effect_journal_handle_testkind_door_guard_tests_chirho`,
//! `testkind_geo_node_confinement_guard_tests_chirho`). An example builds with this dev-only crate's
//! dev-dependencies, which already turn the serve runtime's `dev-llm-served-chirho` feature on, so it
//! changes no manifest and moves no deployed binary's bytes.
//!
//! NAMES NO DOOR. It opens the root through this crate's `testkind_normal_settlement_resident_opener_chirho`
//! and serves through the runtime's own dev entry, which still refuses unless
//! `CAIRN_DEV_LLM_SERVED_CHIRHO=1` and the root is test-kind. It deploys nothing: the root arrives
//! provisioned (identities, app, policies and price book written before the dev bootstrap).
//!
//! Workflow: `spec-chirho/workflows-chirho/provider-boundaries-chirho/llm-served-spend-boundary-chirho.md`.

use anyhow::{anyhow, bail, Context, Result};
use cairn_chirho::effect_chirho::llm_served_chirho::AppPriceBookUserPaysLlmPolicyChirho;
use cairn_config_chirho::config_chirho::{load_config_chirho, LedgerHostConfigChirho};
use cairn_ledger_geo_node_testkind_chirho::testkind_normal_settlement_resident_opener_chirho;
use cairn_ledger_host_chirho::{
    host_ledger_signer_refs_from_config_chirho, require_test_kind_marked_host_config_chirho,
    HostLedgerSignersChirho,
};
use cairn_ledger_model_chirho::ids_chirho::AssetKindIdChirho;
use cairn_llm_served_effect_chirho::{
    LlmProviderChirho, LlmProviderOutcomeChirho, LlmRefusalCodeChirho, LlmRequestChirho,
    StubLlmProviderChirho,
};
use cairn_serve_runtime_chirho::{
    open_shared_llm_served_composition_with_resident_journal_chirho,
    serve_with_dev_llm_served_composition_until_chirho, LedgerHostProjectionReadPortChirho,
    OpenSharedLlmServedCompositionParamsChirho, ServedLlmCardSurfaceChirho,
};
use cairn_served_llm_dev_bootstrap_chirho::SERVED_LLM_DEV_CONFIG_FILE_CHIRHO;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const EXAMPLE_NAME_CHIRHO: &str = "served_llm_dev_serve_chirho";

/// The example's name PLUS the crate version PLUS the source commit that built these bytes, so a
/// gate can bind the binary it runs to its candidate, as it does every other cairn binary.
const VERSION_LINE_CHIRHO: &str =
    cairn_build_identity_chirho::version_line_chirho!("served_llm_dev_serve_chirho");

const USAGE_CHIRHO: &str = "\
usage: served_llm_dev_serve_chirho \
--root-chirho <provisioned test-kind root> \
--port-chirho <loopback port> \
--app-chirho <app> \
--paid-route-chirho <route> \
--billing-kind-chirho <asset kind> \
--stop-file-chirho <path> \
[--ledger-config-chirho <ledger-config.toml>] \
[--refusal-marker-chirho <text>]
  Serves the composed served-LLM card on loopback until the stop file exists, then prints the
  balances again and exits. Needs CAIRN_DEV_LLM_SERVED_CHIRHO=1 and a test-kind root.
  --ledger-config-chirho defaults to <root>/served-llm-dev-config-chirho.toml, which the dev
  bootstrap writes. A brief containing --refusal-marker-chirho gets the stub's typed refusal.";

/// The number of served requests the dev composition admits at once, as in the card e2e.
const INFLIGHT_LIMIT_CHIRHO: usize = 8;
/// How often the stop file is looked for.
const STOP_POLL_CHIRHO: Duration = Duration::from_millis(200);

/// The reviewed inputs, one per flag, so no two can be silently transposed.
struct ServeArgsChirho {
    root_chirho: PathBuf,
    port_chirho: u16,
    app_chirho: String,
    paid_route_chirho: String,
    billing_kind_chirho: String,
    stop_file_chirho: PathBuf,
    ledger_config_chirho: Option<PathBuf>,
    refusal_marker_chirho: Option<String>,
}

/// The stub provider, except that a brief carrying the marker gets the typed provider refusal: the
/// refusal card renders and the whole hold is released, so no charge settles.
struct RefusalMarkerStubProviderChirho {
    marker_chirho: String,
}

impl LlmProviderChirho for RefusalMarkerStubProviderChirho {
    fn complete_chirho(&self, request_chirho: &LlmRequestChirho) -> LlmProviderOutcomeChirho {
        if request_chirho.user_chirho.contains(&self.marker_chirho) {
            return LlmProviderOutcomeChirho::RefusedChirho(
                LlmRefusalCodeChirho::ProviderUnavailableChirho,
            );
        }
        StubLlmProviderChirho.complete_chirho(request_chirho)
    }
}

fn main() -> Result<()> {
    let mut args_chirho = std::env::args_os();
    let _program_chirho = args_chirho.next();
    let rest_chirho: Vec<OsString> = args_chirho.collect();
    if cairn_build_identity_chirho::is_version_request_chirho(
        rest_chirho
            .first()
            .and_then(|arg_chirho| arg_chirho.to_str()),
    ) {
        println!("{VERSION_LINE_CHIRHO}");
        return Ok(());
    }
    let parsed_chirho = parse_args_chirho(rest_chirho.into_iter())?;
    // The runtime's dev entry checks this too and stays the authority; checking it first means a
    // missing opt-in never opens the resident authority only to be refused afterwards.
    if std::env::var("CAIRN_DEV_LLM_SERVED_CHIRHO").ok().as_deref() != Some("1") {
        bail!("{EXAMPLE_NAME_CHIRHO} refused: set CAIRN_DEV_LLM_SERVED_CHIRHO=1 to serve the dev composition");
    }
    serve_dev_card_chirho(parsed_chirho)
}

/// Named apart from the runtime's `serve_chirho` boot door, which the wave-1 boot census matches by name.
fn serve_dev_card_chirho(args_chirho: ServeArgsChirho) -> Result<()> {
    let root_chirho = args_chirho
        .root_chirho
        .canonicalize()
        .with_context(|| format!("the root {} must exist", args_chirho.root_chirho.display()))?;
    let config_path_chirho = args_chirho
        .ledger_config_chirho
        .clone()
        .unwrap_or_else(|| root_chirho.join(SERVED_LLM_DEV_CONFIG_FILE_CHIRHO));
    let ledger_host_chirho = load_config_chirho(&config_path_chirho)
        .with_context(|| format!("load the ledger config {}", config_path_chirho.display()))?
        .ledger_host_chirho
        .ok_or_else(|| anyhow!("the ledger config carries no ledger host block"))?;
    require_test_kind_marked_host_config_chirho(&ledger_host_chirho)?;

    print_balances_chirho(
        "before",
        &root_chirho,
        &config_path_chirho,
        &ledger_host_chirho,
    )?;

    let signers_chirho = HostLedgerSignersChirho::load_existing_chirho(
        &root_chirho,
        &host_ledger_signer_refs_from_config_chirho(&ledger_host_chirho.signer_secrets_chirho)?,
    )?;
    let handle_chirho = testkind_normal_settlement_resident_opener_chirho(
        &root_chirho,
        &config_path_chirho,
        &ledger_host_chirho,
    )?;
    let provider_chirho: Box<dyn LlmProviderChirho + Send + Sync> =
        match args_chirho.refusal_marker_chirho {
            Some(marker_chirho) => Box::new(RefusalMarkerStubProviderChirho { marker_chirho }),
            None => Box::new(StubLlmProviderChirho),
        };
    let composition_chirho = open_shared_llm_served_composition_with_resident_journal_chirho(
        OpenSharedLlmServedCompositionParamsChirho {
            root_chirho: &root_chirho,
            handle_chirho,
            signers_chirho,
            provider_chirho,
            policy_chirho: Box::new(AppPriceBookUserPaysLlmPolicyChirho),
            billing_kind_chirho: AssetKindIdChirho(args_chirho.billing_kind_chirho),
            ledger_config_chirho: &ledger_host_chirho,
            served_surface_chirho: ServedLlmCardSurfaceChirho::new_chirho(
                &args_chirho.app_chirho,
                &args_chirho.paid_route_chirho,
            ),
        },
    )?;

    let stop_chirho = Arc::new(AtomicBool::new(false));
    let watcher_stop_chirho = stop_chirho.clone();
    let stop_file_chirho = args_chirho.stop_file_chirho;
    let watcher_chirho = std::thread::spawn(move || {
        while !watcher_stop_chirho.load(Ordering::Acquire) {
            if stop_file_chirho.exists() {
                watcher_stop_chirho.store(true, Ordering::Release);
                return;
            }
            std::thread::sleep(STOP_POLL_CHIRHO);
        }
    });
    let runtime_chirho = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build the serve runtime")?;
    let served_chirho =
        runtime_chirho.block_on(serve_with_dev_llm_served_composition_until_chirho(
            &root_chirho,
            args_chirho.port_chirho,
            INFLIGHT_LIMIT_CHIRHO,
            String::new(),
            String::new(),
            composition_chirho,
            Some(stop_chirho.clone()),
        ));
    // The serve returned, so the composition and its resident handle are dropped and the ledger is
    // free for the read below. Stop the watcher whichever way the serve ended.
    stop_chirho.store(true, Ordering::Release);
    let _joined_chirho = watcher_chirho.join();
    served_chirho?;
    print_balances_chirho(
        "after",
        &root_chirho,
        &config_path_chirho,
        &ledger_host_chirho,
    )
}

/// One line per account in the verified substrate: `served-llm-dev-balance-chirho phase_chirho=<phase>
/// principal_chirho=<p> kind_chirho=<kind> net_chirho=<n> held_chirho=<n>`, both from the one snapshot.
/// A hold leaves net unchanged while held rises, so a release can only be shown with both. An account
/// absent from one of the two maps has 0 there.
fn print_balances_chirho(
    phase_chirho: &str,
    root_chirho: &Path,
    config_path_chirho: &Path,
    ledger_host_chirho: &LedgerHostConfigChirho,
) -> Result<()> {
    let balances_chirho = LedgerHostProjectionReadPortChirho::open_existing_chirho(
        root_chirho,
        config_path_chirho,
        ledger_host_chirho,
    )?
    .read_substrate_balances_chirho()?;
    let accounts_chirho: std::collections::BTreeSet<&(String, String)> = balances_chirho
        .account_nets_chirho
        .keys()
        .chain(balances_chirho.account_held_chirho.keys())
        .collect();
    for account_chirho in accounts_chirho {
        let (principal_chirho, kind_chirho) = account_chirho;
        let net_chirho = balances_chirho
            .account_nets_chirho
            .get(account_chirho)
            .copied()
            .unwrap_or(0);
        let held_chirho = balances_chirho
            .account_held_chirho
            .get(account_chirho)
            .copied()
            .unwrap_or(0);
        println!(
            "served-llm-dev-balance-chirho phase_chirho={phase_chirho} principal_chirho={principal_chirho} kind_chirho={kind_chirho} net_chirho={net_chirho} held_chirho={held_chirho}"
        );
    }
    Ok(())
}

/// Store a flag's value exactly once: a repeated flag is a refusal, not last-one-wins.
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

fn parse_args_chirho(mut args_chirho: impl Iterator<Item = OsString>) -> Result<ServeArgsChirho> {
    let mut root_chirho = None;
    let mut port_chirho = None;
    let mut app_chirho = None;
    let mut paid_route_chirho = None;
    let mut billing_kind_chirho = None;
    let mut stop_file_chirho = None;
    let mut ledger_config_chirho = None;
    let mut refusal_marker_chirho = None;
    while let Some(raw_flag_chirho) = args_chirho.next() {
        let flag_chirho = raw_flag_chirho
            .into_string()
            .map_err(|raw_chirho| anyhow!("argument is not valid UTF-8: {raw_chirho:?}"))?;
        let value_chirho = args_chirho
            .next()
            .ok_or_else(|| anyhow!("{flag_chirho} needs a value\n{USAGE_CHIRHO}"))?
            .into_string()
            .map_err(|raw_chirho| {
                anyhow!("{flag_chirho} value is not valid UTF-8: {raw_chirho:?}")
            })?;
        let slot_chirho = match flag_chirho.as_str() {
            "--root-chirho" => &mut root_chirho,
            "--port-chirho" => &mut port_chirho,
            "--app-chirho" => &mut app_chirho,
            "--paid-route-chirho" => &mut paid_route_chirho,
            "--billing-kind-chirho" => &mut billing_kind_chirho,
            "--stop-file-chirho" => &mut stop_file_chirho,
            "--ledger-config-chirho" => &mut ledger_config_chirho,
            "--refusal-marker-chirho" => &mut refusal_marker_chirho,
            _ => bail!("unknown argument {flag_chirho:?}\n{USAGE_CHIRHO}"),
        };
        set_once_chirho(slot_chirho, &flag_chirho, value_chirho)?;
    }
    let refusal_marker_chirho = match refusal_marker_chirho {
        Some(marker_chirho) if marker_chirho.is_empty() => {
            bail!("--refusal-marker-chirho must not be empty: it would refuse every brief")
        }
        other_chirho => other_chirho,
    };
    let port_text_chirho = require_chirho(port_chirho, "--port-chirho")?;
    Ok(ServeArgsChirho {
        root_chirho: PathBuf::from(require_chirho(root_chirho, "--root-chirho")?),
        port_chirho: port_text_chirho.parse().map_err(|_| {
            anyhow!("--port-chirho must be a port number, got {port_text_chirho:?}")
        })?,
        app_chirho: require_chirho(app_chirho, "--app-chirho")?,
        paid_route_chirho: require_chirho(paid_route_chirho, "--paid-route-chirho")?,
        billing_kind_chirho: require_chirho(billing_kind_chirho, "--billing-kind-chirho")?,
        stop_file_chirho: PathBuf::from(require_chirho(stop_file_chirho, "--stop-file-chirho")?),
        ledger_config_chirho: ledger_config_chirho.map(PathBuf::from),
        refusal_marker_chirho,
    })
}
