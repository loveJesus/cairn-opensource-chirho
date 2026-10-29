// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Runs the item-6 drill-root layout validator against ONE staged root on the host that holds it.
//!
//! WHY THIS EXISTS: 6.5-b shipped `validate_item6_drill_root_layout_chirho` as a library function
//! with **no way to execute it on a host**. Every binding it checks — file custody (owner + mode),
//! the derived consistency group, the canonicalized config-root binding, the symlink-resolved
//! forbidden-root backstop, and the persisted writer-authority era — reads the REAL filesystem, so
//! the check cannot be run from a workstation against a remote path. A preflight nobody can run is
//! a preflight nobody has run, so 6.5-e-3 adds the runner rather than eyeballing the layout.
//!
//! It creates nothing, signs nothing, binds no port, and serves nothing: it validates and prints.
//! On success it emits the resolved layout evidence as JSON; on refusal it exits non-zero with the
//! validator's own named reason, so an operator reads WHICH binding refused rather than "failed".

use anyhow::{anyhow, Result};
use cairn_drill_root_layout_chirho::{
    validate_item6_drill_root_layout_chirho, Item6DrillRootLayoutChirho,
    CANONICAL_ITEM6_DRILL_NAMESPACE_CHIRHO,
};
use std::path::PathBuf;

/// This binary's name PLUS the crate version PLUS the source commit that built these bytes.
///
/// A preflight verdict is only as trustworthy as the code that produced it, and a sha256 on a host
/// resolves to a tree only if the bytes carry the commit.
const VERSION_LINE_CHIRHO: &str =
    cairn_build_identity_chirho::version_line_chirho!("cairn-drill-root-layout-verify-chirho");

const USAGE_CHIRHO: &str = "usage: cairn-drill-root-layout-verify-chirho <selected-root> <cluster-config.json> <ledger-config.toml> [drill-namespace]";

fn main() -> Result<()> {
    let mut args_chirho = std::env::args_os();
    let _program_chirho = args_chirho.next();
    // BEFORE the positional parse: argv[1] becomes a PATH below, so a version request would
    // otherwise be read as a directory name and answered with a confusing custody error.
    let first_arg_chirho = args_chirho.next();
    if cairn_build_identity_chirho::is_version_request_chirho(
        first_arg_chirho
            .as_ref()
            .and_then(|arg_chirho| arg_chirho.to_str()),
    ) {
        println!("{VERSION_LINE_CHIRHO}");
        return Ok(());
    }
    let selected_root_chirho = first_arg_chirho
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!(USAGE_CHIRHO))?;
    let cluster_config_chirho = args_chirho
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!(USAGE_CHIRHO))?;
    let ledger_config_chirho = args_chirho
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!(USAGE_CHIRHO))?;
    // The namespace is parameterized ONLY so a non-canonical staging area can be validated
    // deliberately; omitting it takes the canonical hosted drill namespace. The forbidden
    // production/elector roots stay fixed constants either way, so no argument can widen them.
    let drill_namespace_chirho = args_chirho
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(CANONICAL_ITEM6_DRILL_NAMESPACE_CHIRHO));
    if args_chirho.next().is_some() {
        return Err(anyhow!(USAGE_CHIRHO));
    }

    let layout_chirho = Item6DrillRootLayoutChirho {
        selected_root_chirho,
        drill_namespace_chirho,
        cluster_config_chirho,
        ledger_config_chirho,
    };
    let resolved_chirho = validate_item6_drill_root_layout_chirho(&layout_chirho)?;
    println!("{}", serde_json::to_string_pretty(&resolved_chirho)?);
    Ok(())
}
