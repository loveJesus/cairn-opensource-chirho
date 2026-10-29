// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Porcelain scaffolding for the directory-structure-IS-DAG tree: create dags, nodes, and wires as
//! plain filesystem operations, so an author (or an LLM) composes an app with a handful of commands
//! instead of hand-built symlinks. Everything produced here is validated by `tree-build check`.
//!
//! Grammar (mirrors the checked-in demo trees):
//! ```text
//!   dags_chirho/<dag>/spec-chirho.toml                          — dag spec
//!   dags_chirho/<dag>/surface_chirho/in-<name>-<type>-chirho/   — surface input (a .gitkeep dir)
//!   dags_chirho/<dag>/surface_chirho/out-<name>-<type>-chirho   — surface output (a wire symlink)
//!   dags_chirho/<dag>/nodes_chirho/<role>/spec-chirho.toml      — node spec
//!   dags_chirho/<dag>/nodes_chirho/<role>/out-<name>-<type>-chirho/ — node output (a .gitkeep dir)
//!   dags_chirho/<dag>/nodes_chirho/<role>/in-<name>-<type>-chirho   — node input (a wire symlink)
//!   dags_chirho/<dag>/nodes_chirho/<role>/<role>.rs            — impl binding (a symlink into src/)
//!   dags_chirho/<dag>/nodes_chirho/<role>/blessed-contract-chirho.toml — blessed binding
//!   dags_chirho/<dag>/effects_chirho/.gitkeep
//! ```

use crate::blessed_catalog_chirho::{
    lookup_blessed_contract_chirho, validate_blessed_card_v2_envelope_chirho,
    BlessedCardParamsChirho, BLESSED_CARD_SCHEMA_V2_CHIRHO,
};
use serde::Serialize;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Component, Path, PathBuf};

const HEADER_CHIRHO: &str = "# For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16\n";
const RUST_HEADER_CHIRHO: &str = "// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16\n";
const CONTACT_FORM_HTML_CHIRHO: &str = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Contact</title><link rel=\"stylesheet\" href=\"/app-assets-chirho/starter-contact-chirho/by-name-chirho/starter-contact-chirho.css\"></head><body><main><h1>Contact us</h1><form method=\"post\" action=\"/contact-chirho\"><label>Name <input name=\"name_chirho\"></label><label>Email <input name=\"email_chirho\" type=\"email\"></label><label>Message <textarea name=\"message_chirho\"></textarea></label><button type=\"submit\">Send</button></form></main></body></html>";
const CONTACT_FORM_CSS_CHIRHO: &str =
    "body{font-family:system-ui,sans-serif;margin:2rem}label{display:block;margin:.75rem 0}\n";

/// A `name:type` port declaration (e.g. `request:http_request_v1`).
pub struct PortSpecChirho {
    pub name_chirho: String,
    pub type_chirho: String,
}

/// Author-controlled fields accepted by the `blessed-add` porcelain boundary.
pub struct BlessedNodeSpecChirho<'a> {
    pub contract_chirho: &'a str,
    pub scope_chirho: &'a str,
    pub caller_chirho: Option<&'a str>,
    pub max_rows_chirho: Option<u64>,
    pub max_tokens_chirho: Option<u64>,
    pub max_price_per_token_chirho: Option<i64>,
    pub intent_chirho: &'a str,
}

#[derive(Serialize)]
struct BlessedCardFileChirho<'a> {
    schema_chirho: &'static str,
    contract_chirho: &'a str,
    contract_hash_chirho: String,
    scope_chirho: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    caller_chirho: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_rows_chirho: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens_chirho: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_price_per_token_chirho: Option<i64>,
    intent_chirho: &'a str,
}

/// Parse a `name:type` port declaration.
pub fn parse_port_spec_chirho(spec_chirho: &str) -> Result<PortSpecChirho, String> {
    let (name_chirho, type_chirho) = spec_chirho
        .split_once(':')
        .ok_or_else(|| format!("port '{spec_chirho}' must be name:type"))?;
    let name_chirho = name_chirho.trim();
    let type_chirho = type_chirho.trim();
    if name_chirho.is_empty() || type_chirho.is_empty() {
        return Err(format!("port '{spec_chirho}' must be name:type"));
    }
    validate_ident_chirho("port name", name_chirho)?;
    validate_ident_chirho("port type", type_chirho)?;
    Ok(PortSpecChirho {
        name_chirho: name_chirho.to_string(),
        type_chirho: type_chirho.to_string(),
    })
}

/// Reject names that aren't safe filesystem segments — the porcelain is the author-supplied trust
/// boundary, so a name like `../etc` must never reach a path. Lowercase letters, digits, and
/// underscores only (the segment grammar).
fn validate_ident_chirho(label_chirho: &str, value_chirho: &str) -> Result<(), String> {
    let ok_chirho = !value_chirho.is_empty()
        && value_chirho.bytes().all(|b_chirho| {
            b_chirho.is_ascii_lowercase() || b_chirho.is_ascii_digit() || b_chirho == b'_'
        });
    if !ok_chirho {
        return Err(format!(
            "{label_chirho} '{value_chirho}' must be lowercase letters, digits, and underscores only (no path separators)"
        ));
    }
    Ok(())
}

/// The directory name for a port: `<dir>-<name>-<type>-chirho` (dir is `in` or `out`).
fn port_dir_name_chirho(dir_chirho: &str, port_chirho: &PortSpecChirho) -> String {
    format!(
        "{dir_chirho}-{}-{}-chirho",
        port_chirho.name_chirho, port_chirho.type_chirho
    )
}

fn create_dir_chirho(dir_chirho: &Path) -> Result<(), String> {
    fs::create_dir_all(dir_chirho)
        .map_err(|e_chirho| format!("create {}: {e_chirho}", dir_chirho.display()))
}

fn write_new_chirho(path_chirho: &Path, contents_chirho: &str) -> Result<(), String> {
    if path_chirho.exists() {
        return Err(format!("{} already exists", path_chirho.display()));
    }
    fs::write(path_chirho, contents_chirho)
        .map_err(|e_chirho| format!("write {}: {e_chirho}", path_chirho.display()))
}

fn ensure_empty_dir_chirho(dir_chirho: &Path) -> Result<(), String> {
    if dir_chirho.exists() {
        let mut entries_chirho = fs::read_dir(dir_chirho)
            .map_err(|e_chirho| format!("read {}: {e_chirho}", dir_chirho.display()))?;
        if entries_chirho.next().is_some() {
            return Err(format!("{} is not empty", dir_chirho.display()));
        }
    } else {
        create_dir_chirho(dir_chirho)?;
    }
    Ok(())
}

fn gitkeep_dir_chirho(dir_chirho: &Path) -> Result<(), String> {
    create_dir_chirho(dir_chirho)?;
    let keep_chirho = dir_chirho.join(".gitkeep");
    if !keep_chirho.exists() {
        fs::write(&keep_chirho, b"")
            .map_err(|e_chirho| format!("write {}: {e_chirho}", keep_chirho.display()))?;
    }
    Ok(())
}

fn toml_list_chirho(ports_chirho: &[PortSpecChirho]) -> String {
    ports_chirho
        .iter()
        .map(|p_chirho| format!("\"{}: {}\"", p_chirho.name_chirho, p_chirho.type_chirho))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `dag-new`: scaffold a new dag — its spec, surface input dirs, and effects dir. Surface outputs
/// are declared in the spec and become wires (created by `wire`).
pub fn dag_new_chirho(
    app_root_chirho: &Path,
    dag_chirho: &str,
    ins_chirho: &[PortSpecChirho],
    outs_chirho: &[PortSpecChirho],
) -> Result<String, String> {
    validate_ident_chirho("dag name", dag_chirho)?;
    let dag_dir_chirho = app_root_chirho.join("dags_chirho").join(dag_chirho);
    if dag_dir_chirho.exists() {
        return Err(format!("dag '{dag_chirho}' already exists"));
    }
    create_dir_chirho(&dag_dir_chirho)?;
    let spec_chirho = format!(
        "{HEADER_CHIRHO}schema_chirho = \"dag-spec-v0-chirho\"\n\
intent_chirho = \"TODO: what this dag does.\"\n\
surface_chirho = {{ ins_chirho = [{ins_chirho}], outs_chirho = [{outs_chirho}] }}\n\
structure_chirho = [\n  \"TODO: the structural rule(s) this dag must hold\",\n]\n\
behaviors_chirho = [\n  \"TODO: an observable behavior\",\n]\n",
        ins_chirho = toml_list_chirho(ins_chirho),
        outs_chirho = toml_list_chirho(outs_chirho),
    );
    write_new_chirho(&dag_dir_chirho.join("spec-chirho.toml"), &spec_chirho)?;
    for in_chirho in ins_chirho {
        gitkeep_dir_chirho(
            &dag_dir_chirho
                .join("surface_chirho")
                .join(port_dir_name_chirho("in", in_chirho)),
        )?;
    }
    gitkeep_dir_chirho(&dag_dir_chirho.join("effects_chirho"))?;
    Ok(format!(
        "dag '{dag_chirho}' created ({} in, {} out). Next: node-add, then wire the surface outs.",
        ins_chirho.len(),
        outs_chirho.len()
    ))
}

/// `node-add`: scaffold a pure node in a dag — its spec, output dirs, and the impl symlink into
/// `src/implementations_chirho/<impl>.rs`. Inputs become wires (created by `wire`).
pub fn node_add_chirho(
    app_root_chirho: &Path,
    dag_chirho: &str,
    role_chirho: &str,
    ins_chirho: &[PortSpecChirho],
    outs_chirho: &[PortSpecChirho],
    impl_module_chirho: &str,
) -> Result<String, String> {
    validate_ident_chirho("dag name", dag_chirho)?;
    validate_ident_chirho("role name", role_chirho)?;
    validate_ident_chirho("impl module", impl_module_chirho)?;
    let dag_dir_chirho = app_root_chirho.join("dags_chirho").join(dag_chirho);
    if !dag_dir_chirho.exists() {
        return Err(format!(
            "dag '{dag_chirho}' does not exist (run dag-new first)"
        ));
    }
    let node_dir_chirho = dag_dir_chirho.join("nodes_chirho").join(role_chirho);
    if node_dir_chirho.exists() {
        return Err(format!(
            "node '{role_chirho}' already exists in dag '{dag_chirho}'"
        ));
    }
    create_dir_chirho(&node_dir_chirho)?;
    let behaviors_chirho = ins_chirho
        .iter()
        .map(|p_chirho| {
            format!(
                "  \"reads {} ({})\",",
                p_chirho.name_chirho, p_chirho.type_chirho
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let spec_chirho = format!(
        "{HEADER_CHIRHO}schema_chirho = \"node-spec-v0-chirho\"\n\
intent_chirho = \"TODO: what {role_chirho} does.\"\n\
behaviors_chirho = [\n{behaviors_chirho}\n]\n",
    );
    write_new_chirho(&node_dir_chirho.join("spec-chirho.toml"), &spec_chirho)?;
    for out_chirho in outs_chirho {
        gitkeep_dir_chirho(&node_dir_chirho.join(port_dir_name_chirho("out", out_chirho)))?;
    }
    // impl binding: <role>.rs -> ../../../../src/implementations_chirho/<impl>.rs
    let impl_link_chirho = node_dir_chirho.join(format!("{role_chirho}.rs"));
    let impl_target_chirho =
        format!("../../../../src/implementations_chirho/{impl_module_chirho}.rs");
    symlink(&impl_target_chirho, &impl_link_chirho).map_err(|e_chirho| {
        format!(
            "link {} -> {impl_target_chirho}: {e_chirho}",
            impl_link_chirho.display()
        )
    })?;
    Ok(format!(
        "node '{role_chirho}' added to '{dag_chirho}' ({} in, {} out). Wire its inputs next; \
write the impl at src/implementations_chirho/{impl_module_chirho}.rs.",
        ins_chirho.len(),
        outs_chirho.len()
    ))
}

/// `blessed-add`: scaffold one catalog-pinned blessed role. The command can request an existing
/// contract but cannot define or mint one; the real checker remains authoritative over the card.
pub fn blessed_add_chirho(
    app_root_chirho: &Path,
    dag_chirho: &str,
    role_chirho: &str,
    ins_chirho: &[PortSpecChirho],
    outs_chirho: &[PortSpecChirho],
    node_chirho: &BlessedNodeSpecChirho<'_>,
) -> Result<String, String> {
    validate_ident_chirho("dag name", dag_chirho)?;
    validate_ident_chirho("role name", role_chirho)?;
    validate_blessed_card_v2_envelope_chirho(
        BLESSED_CARD_SCHEMA_V2_CHIRHO,
        node_chirho.intent_chirho,
        None,
    )?;
    let entry_chirho = lookup_blessed_contract_chirho(node_chirho.contract_chirho)
        .ok_or_else(|| format!("unknown blessed contract '{}'", node_chirho.contract_chirho))?;
    entry_chirho.capabilities_for_card_chirho(&BlessedCardParamsChirho {
        scope_chirho: node_chirho.scope_chirho,
        caller_chirho: node_chirho.caller_chirho,
        max_rows_chirho: node_chirho.max_rows_chirho,
        max_tokens_chirho: node_chirho.max_tokens_chirho,
        max_price_per_token_chirho: node_chirho.max_price_per_token_chirho,
    })?;

    let dag_dir_chirho = app_root_chirho.join("dags_chirho").join(dag_chirho);
    if !dag_dir_chirho.exists() {
        return Err(format!(
            "dag '{dag_chirho}' does not exist (run dag-new first)"
        ));
    }
    let node_dir_chirho = dag_dir_chirho.join("nodes_chirho").join(role_chirho);
    if node_dir_chirho.exists() {
        return Err(format!(
            "node '{role_chirho}' already exists in dag '{dag_chirho}'"
        ));
    }
    create_dir_chirho(&node_dir_chirho)?;
    let behaviors_chirho = ins_chirho
        .iter()
        .map(|port_chirho| {
            format!(
                "  \"reads {} ({})\",",
                port_chirho.name_chirho, port_chirho.type_chirho
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let spec_chirho = format!(
        "{HEADER_CHIRHO}schema_chirho = \"node-spec-v0-chirho\"\n\
intent_chirho = {intent_chirho:?}\n\
behaviors_chirho = [\n{behaviors_chirho}\n]\n",
        intent_chirho = node_chirho.intent_chirho,
    );
    write_new_chirho(&node_dir_chirho.join("spec-chirho.toml"), &spec_chirho)?;
    for out_chirho in outs_chirho {
        gitkeep_dir_chirho(&node_dir_chirho.join(port_dir_name_chirho("out", out_chirho)))?;
    }

    let card_body_chirho = toml::to_string_pretty(&BlessedCardFileChirho {
        schema_chirho: BLESSED_CARD_SCHEMA_V2_CHIRHO,
        contract_chirho: node_chirho.contract_chirho,
        contract_hash_chirho: entry_chirho.contract_hash_chirho(),
        scope_chirho: node_chirho.scope_chirho,
        caller_chirho: node_chirho.caller_chirho,
        max_rows_chirho: node_chirho.max_rows_chirho,
        max_tokens_chirho: node_chirho.max_tokens_chirho,
        max_price_per_token_chirho: node_chirho.max_price_per_token_chirho,
        intent_chirho: node_chirho.intent_chirho,
    })
    .map_err(|error_chirho| format!("encode blessed card: {error_chirho}"))?;
    write_new_chirho(
        &node_dir_chirho.join("blessed-contract-chirho.toml"),
        &format!("{HEADER_CHIRHO}{card_body_chirho}"),
    )?;
    Ok(format!(
        "blessed node '{role_chirho}' added to '{dag_chirho}' under catalog contract '{}' ({} in, {} out). Wire its ports next.",
        node_chirho.contract_chirho,
        ins_chirho.len(),
        outs_chirho.len()
    ))
}

/// Resolve `owner:port` (owner is `surface` or a role) to the existing producer port directory name.
fn find_port_dir_chirho(
    dir_chirho: &Path,
    prefix_chirho: &str,
    port_name_chirho: &str,
) -> Result<String, String> {
    let needle_chirho = format!("{prefix_chirho}-{port_name_chirho}-");
    let entries_chirho = fs::read_dir(dir_chirho)
        .map_err(|e_chirho| format!("read {}: {e_chirho}", dir_chirho.display()))?;
    for entry_chirho in entries_chirho.flatten() {
        let name_chirho = entry_chirho.file_name().to_string_lossy().to_string();
        if name_chirho.starts_with(&needle_chirho) {
            return Ok(name_chirho);
        }
    }
    Err(format!(
        "no {prefix_chirho} port named '{port_name_chirho}' in {}",
        dir_chirho.display()
    ))
}

/// `wire`: connect a producer port to a consumer port with a symlink (data flows producer -> consumer).
/// `from`/`to` are `surface:<port>` or `<role>:<port>`. Exactly one of from/to is `surface`.
pub fn wire_chirho(
    app_root_chirho: &Path,
    dag_chirho: &str,
    from_chirho: &str,
    to_chirho: &str,
) -> Result<String, String> {
    validate_ident_chirho("dag name", dag_chirho)?;
    let dag_dir_chirho = app_root_chirho.join("dags_chirho").join(dag_chirho);
    if !dag_dir_chirho.exists() {
        return Err(format!("dag '{dag_chirho}' does not exist"));
    }
    let (from_owner_chirho, from_port_chirho) = from_chirho
        .split_once(':')
        .ok_or_else(|| format!("from '{from_chirho}' must be owner:port"))?;
    let (to_owner_chirho, to_port_chirho) = to_chirho
        .split_once(':')
        .ok_or_else(|| format!("to '{to_chirho}' must be owner:port"))?;
    for ident_chirho in [
        from_owner_chirho,
        from_port_chirho,
        to_owner_chirho,
        to_port_chirho,
    ] {
        validate_ident_chirho("wire owner/port", ident_chirho)?;
    }

    if to_owner_chirho == "surface" {
        // surface output <- node output: link at surface_chirho/out-... -> ../nodes_chirho/<role>/out-...
        let producer_dir_chirho = dag_dir_chirho.join("nodes_chirho").join(from_owner_chirho);
        let producer_port_chirho =
            find_port_dir_chirho(&producer_dir_chirho, "out", from_port_chirho)?;
        // the surface out dir name reuses the producer's type: out-<to_port>-<type>-chirho
        let type_chirho = port_type_from_dir_chirho(&producer_port_chirho)?;
        let surface_out_chirho = format!("out-{to_port_chirho}-{type_chirho}-chirho");
        create_dir_chirho(&dag_dir_chirho.join("surface_chirho"))?;
        let link_chirho = dag_dir_chirho
            .join("surface_chirho")
            .join(&surface_out_chirho);
        let target_chirho = format!("../nodes_chirho/{from_owner_chirho}/{producer_port_chirho}");
        symlink_new_chirho(&target_chirho, &link_chirho)?;
        return Ok(format!(
            "wired surface:{to_port_chirho} <- {from_owner_chirho}:{from_port_chirho}"
        ));
    }

    // consumer is a node input: link at nodes_chirho/<to_role>/in-... -> producer
    let consumer_dir_chirho = dag_dir_chirho.join("nodes_chirho").join(to_owner_chirho);
    if !consumer_dir_chirho.exists() {
        return Err(format!(
            "node '{to_owner_chirho}' does not exist in dag '{dag_chirho}'"
        ));
    }
    let (type_chirho, target_chirho) = if from_owner_chirho == "surface" {
        let producer_port_chirho = find_port_dir_chirho(
            &dag_dir_chirho.join("surface_chirho"),
            "in",
            from_port_chirho,
        )?;
        let type_chirho = port_type_from_dir_chirho(&producer_port_chirho)?;
        let target_chirho = format!("../../surface_chirho/{producer_port_chirho}");
        (type_chirho, target_chirho)
    } else {
        let producer_dir_chirho = dag_dir_chirho.join("nodes_chirho").join(from_owner_chirho);
        let producer_port_chirho =
            find_port_dir_chirho(&producer_dir_chirho, "out", from_port_chirho)?;
        let type_chirho = port_type_from_dir_chirho(&producer_port_chirho)?;
        let target_chirho = format!("../{from_owner_chirho}/{producer_port_chirho}");
        (type_chirho, target_chirho)
    };
    let consumer_in_chirho = format!("in-{to_port_chirho}-{type_chirho}-chirho");
    let link_chirho = consumer_dir_chirho.join(&consumer_in_chirho);
    symlink_new_chirho(&target_chirho, &link_chirho)?;
    Ok(format!(
        "wired {to_owner_chirho}:{to_port_chirho} <- {from_owner_chirho}:{from_port_chirho}"
    ))
}

/// The `<type>` segment from a port dir name `<dir>-<name>-<type>-chirho`.
fn port_type_from_dir_chirho(dir_name_chirho: &str) -> Result<String, String> {
    let stem_chirho = dir_name_chirho
        .strip_suffix("-chirho")
        .ok_or_else(|| format!("port dir '{dir_name_chirho}' missing -chirho suffix"))?;
    // stem = <dir>-<name>-<type>; the type is the last dash-segment.
    let type_chirho = stem_chirho
        .rsplit('-')
        .next()
        .ok_or_else(|| format!("port dir '{dir_name_chirho}' has no type segment"))?;
    Ok(type_chirho.to_string())
}

fn symlink_new_chirho(target_chirho: &str, link_chirho: &Path) -> Result<(), String> {
    if link_chirho.exists() || fs::symlink_metadata(link_chirho).is_ok() {
        return Err(format!("{} already exists", link_chirho.display()));
    }
    symlink(target_chirho, link_chirho).map_err(|e_chirho| {
        format!(
            "link {} -> {target_chirho}: {e_chirho}",
            link_chirho.display()
        )
    })
}

/// `new`: scaffold a full starter app tree from a named template.
pub fn new_app_chirho(
    app_root_chirho: &Path,
    template_chirho: &str,
    sdk_dep_mode_chirho: &str,
    sdk_git_rev_chirho: Option<&str>,
) -> Result<String, String> {
    match template_chirho {
        "contact-form-chirho" => {
            new_contact_form_app_chirho(app_root_chirho, sdk_dep_mode_chirho, sdk_git_rev_chirho)
        }
        other_chirho => Err(format!(
            "unknown template '{other_chirho}' (available: contact-form-chirho)"
        )),
    }
}

fn new_contact_form_app_chirho(
    app_root_chirho: &Path,
    sdk_dep_mode_chirho: &str,
    sdk_git_rev_chirho: Option<&str>,
) -> Result<String, String> {
    ensure_empty_dir_chirho(app_root_chirho)?;

    let dep_str_chirho = match sdk_dep_mode_chirho {
        "git" => {
            let rev_chirho = sdk_git_rev_chirho.ok_or_else(|| {
                "git SDK dependency mode requires --sdk-git-rev <rev>".to_string()
            })?;
            validate_git_rev_chirho(rev_chirho)?;
            // json-chirho rides along so the documented export_json_node_chirho path works out of
            // the box (the CF7 dogfood's F5 finding: a template without it fails on first JSON node).
            format!("cairn-node-sdk-chirho = {{ git = \"https://github.com/loveJesus/cairn-opensource-chirho.git\", rev = \"{}\", features = [\"json-chirho\"] }}", rev_chirho)
        }
        _ => {
            let sdk_path_chirho = relative_path_from_app_chirho(
                app_root_chirho,
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .ancestors()
                    .nth(3)
                    .expect("tree-build crate should live below workspace root")
                    .join("crates/cairn-node-sdk-chirho"),
            )?;
            format!(
                "cairn-node-sdk-chirho = {{ path = \"{}\", features = [\"json-chirho\"] }}",
                sdk_path_chirho.display()
            )
        }
    };

    create_dir_chirho(&app_root_chirho.join("src/implementations_chirho"))?;
    create_dir_chirho(&app_root_chirho.join("src/types_chirho"))?;
    create_dir_chirho(&app_root_chirho.join("assets_chirho"))?;
    create_dir_chirho(&app_root_chirho.join("examples"))?;
    create_dir_chirho(&app_root_chirho.join("fixtures_chirho/node-tests-chirho"))?;
    create_dir_chirho(&app_root_chirho.join("fixtures_chirho/node-inputs-chirho"))?;
    create_dir_chirho(&app_root_chirho.join("fixtures_chirho/node-expected-chirho"))?;

    write_new_chirho(
        &app_root_chirho.join("Cargo.toml"),
        &format!(
            "{HEADER_CHIRHO}[package]\n\
name = \"starter-contact-chirho\"\n\
version = \"0.1.0\"\n\
edition = \"2021\"\n\
description = \"Starter contact form app emitted by tree-build-chirho.\"\n\
license = \"MIT\"\n\n\
[workspace]\n\n\
[lib]\n\
crate-type = [\"cdylib\", \"rlib\"]\n\n\
[dependencies]\n\
serde = {{ version = \"1\", features = [\"derive\"] }}\n\
serde_json = \"1\"\n\
{}\n\n\
[[example]]\n\
name = \"render_contact_form_guest_chirho\"\n\
path = \"examples/render_contact_form_guest_chirho.rs\"\n\
crate-type = [\"cdylib\"]\n",
            dep_str_chirho
        ),
    )?;
    write_new_chirho(
        &app_root_chirho.join("app-chirho.toml"),
        &format!(
            "{HEADER_CHIRHO}# App-level descriptor for the starter contact form.\n\
schema_chirho = \"app-descriptor-v0-chirho\"\n\
app_chirho = \"starter-contact-chirho\"\n\
owner_chirho = \"owner/replace-with-local-owner-principal\"\n\
package_chirho = \"starter-contact-chirho\"\n\n\
[root_chirho]\n\
dag_chirho = \"view_contact_chirho\"\n\
input_mode_chirho = \"plain\"\n\
route_label_chirho = \"contact-chirho\"\n\n\
[[asset_chirho]]\n\
name_chirho = \"starter-contact-chirho.css\"\n\
path_chirho = \"assets_chirho/starter-contact-chirho.css\"\n\
content_type_chirho = \"text/css\"\n",
        ),
    )?;
    write_new_chirho(
        &app_root_chirho.join("assets_chirho/starter-contact-chirho.css"),
        CONTACT_FORM_CSS_CHIRHO,
    )?;
    write_new_chirho(
        &app_root_chirho.join("src/lib.rs"),
        &format!(
            "{RUST_HEADER_CHIRHO}\n//! Starter contact form app generated by tree-build-chirho.\n\n\
pub mod implementations_chirho;\n\
pub mod types_chirho;\n"
        ),
    )?;
    write_new_chirho(
        &app_root_chirho.join("src/implementations_chirho.rs"),
        &format!(
            "{RUST_HEADER_CHIRHO}\n//! Pure app node implementations.\n\n\
pub mod render_contact_form_chirho;\n"
        ),
    )?;
    write_new_chirho(
        &app_root_chirho.join("src/types_chirho.rs"),
        &format!(
            "{RUST_HEADER_CHIRHO}\n//! App boundary value types.\n\n\
pub mod http_request_v1_chirho;\n"
        ),
    )?;
    write_new_chirho(
        &app_root_chirho.join("src/types_chirho/http_request_v1_chirho.rs"),
        &format!(
            "{RUST_HEADER_CHIRHO}\nuse serde::{{Deserialize, Serialize}};\n\n\
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]\n\
pub struct HttpRequestV1Chirho {{\n\
    #[serde(default)]\n\
    pub path_chirho: String,\n\
}}\n"
        ),
    )?;
    write_new_chirho(
        &app_root_chirho.join("src/implementations_chirho/render_contact_form_chirho.rs"),
        &format!(
            "{RUST_HEADER_CHIRHO}\n//! Render the starter contact form. This node is pure; it cannot save data or send messages.\n\n\
use crate::types_chirho::http_request_v1_chirho::HttpRequestV1Chirho;\n\n\
pub const CONTACT_FORM_HTML_CHIRHO: &str = r#\"{CONTACT_FORM_HTML_CHIRHO}\"#;\n\n\
pub fn render_contact_form_chirho(_request_chirho: &HttpRequestV1Chirho) -> String {{\n\
    CONTACT_FORM_HTML_CHIRHO.to_string()\n\
}}\n\n\
#[cfg(test)]\n\
mod tests_chirho {{\n\
    use super::*;\n\n\
    #[test]\n\
    fn contact_form_contains_expected_controls_chirho() {{\n\
        let html_chirho = render_contact_form_chirho(&HttpRequestV1Chirho::default());\n\
        assert!(html_chirho.contains(\"name_chirho\"));\n\
        assert!(html_chirho.contains(\"email_chirho\"));\n\
        assert!(html_chirho.contains(\"message_chirho\"));\n\
    }}\n\
}}\n"
        ),
    )?;
    write_new_chirho(
        &app_root_chirho.join("examples/render_contact_form_guest_chirho.rs"),
        &format!(
            "{RUST_HEADER_CHIRHO}\n//! Bytes-ABI guest wrapper for the starter contact-form render node.\n\n\
use starter_contact_chirho::implementations_chirho::render_contact_form_chirho::render_contact_form_chirho as render_contact_form_html_chirho;\n\
use starter_contact_chirho::types_chirho::http_request_v1_chirho::HttpRequestV1Chirho;\n\n\
fn render_contact_form_impl_chirho(input_chirho: &[u8]) -> Vec<u8> {{\n\
    let request_chirho = serde_json::from_slice::<HttpRequestV1Chirho>(input_chirho).unwrap_or_default();\n\
    render_contact_form_html_chirho(&request_chirho).into_bytes()\n\
}}\n\n\
cairn_node_sdk_chirho::export_bytes_node_chirho!(render_contact_form_chirho, render_contact_form_impl_chirho);\n"
        ),
    )?;
    let expected_hash_chirho = blake3::hash(CONTACT_FORM_HTML_CHIRHO.as_bytes())
        .to_hex()
        .to_string();
    write_new_chirho(
        &app_root_chirho.join(
            "fixtures_chirho/node-inputs-chirho/render_contact_form_default_request_chirho.json",
        ),
        "{}\n",
    )?;
    write_new_chirho(
        &app_root_chirho.join(
            "fixtures_chirho/node-expected-chirho/render_contact_form_default_output_chirho.html",
        ),
        CONTACT_FORM_HTML_CHIRHO,
    )?;
    write_new_chirho(
        &app_root_chirho
            .join("fixtures_chirho/node-tests-chirho/render_contact_form_default_chirho.toml"),
        &format!(
            "{HEADER_CHIRHO}schema_chirho = \"tree-build-node-fixture-v1-chirho\"\n\
fixture_chirho = \"render_contact_form_default_chirho\"\n\
node_chirho = \"view_contact_chirho/render_contact_form_chirho\"\n\
wasm_chirho = \"target/wasm32-unknown-unknown/debug/examples/render_contact_form_guest_chirho.wasm\"\n\
entry_chirho = \"render_contact_form_chirho\"\n\
input_chirho = \"fixtures_chirho/node-inputs-chirho/render_contact_form_default_request_chirho.json\"\n\
expected_output_chirho = \"fixtures_chirho/node-expected-chirho/render_contact_form_default_output_chirho.html\"\n\
expected_output_blake3_chirho = \"{expected_hash_chirho}\"\n\
fuel_limit_chirho = 10000000\n\
max_output_bytes_chirho = 1048576\n\
max_memory_bytes_chirho = 67108864\n",
        ),
    )?;

    let in_ports_chirho = vec![parse_port_spec_chirho("request:http_request_v1")?];
    let out_ports_chirho = vec![parse_port_spec_chirho("page:html_partial_v1")?];
    dag_new_chirho(
        app_root_chirho,
        "view_contact_chirho",
        &in_ports_chirho,
        &out_ports_chirho,
    )?;
    node_add_chirho(
        app_root_chirho,
        "view_contact_chirho",
        "render_contact_form_chirho",
        &in_ports_chirho,
        &out_ports_chirho,
        "render_contact_form_chirho",
    )?;
    wire_chirho(
        app_root_chirho,
        "view_contact_chirho",
        "surface:request",
        "render_contact_form_chirho:request",
    )?;
    wire_chirho(
        app_root_chirho,
        "view_contact_chirho",
        "render_contact_form_chirho:page",
        "surface:page",
    )?;
    Ok(format!(
        "new app created at {} from contact-form-chirho. Next: tree-build-chirho check {}",
        app_root_chirho.display(),
        app_root_chirho.display()
    ))
}

fn relative_path_from_app_chirho(
    app_root_chirho: &Path,
    target_chirho: PathBuf,
) -> Result<PathBuf, String> {
    let app_abs_chirho = app_root_chirho
        .canonicalize()
        .map_err(|e_chirho| format!("canonicalize {}: {e_chirho}", app_root_chirho.display()))?;
    let target_abs_chirho = target_chirho
        .canonicalize()
        .map_err(|e_chirho| format!("canonicalize {}: {e_chirho}", target_chirho.display()))?;
    relative_path_chirho(&app_abs_chirho, &target_abs_chirho)
}

fn relative_path_chirho(from_chirho: &Path, to_chirho: &Path) -> Result<PathBuf, String> {
    let from_components_chirho = from_chirho.components().collect::<Vec<_>>();
    let to_components_chirho = to_chirho.components().collect::<Vec<_>>();
    if from_components_chirho.first() != to_components_chirho.first() {
        return Err(format!(
            "cannot make relative path from {} to {}",
            from_chirho.display(),
            to_chirho.display()
        ));
    }
    let mut shared_chirho = 0usize;
    while shared_chirho < from_components_chirho.len()
        && shared_chirho < to_components_chirho.len()
        && from_components_chirho[shared_chirho] == to_components_chirho[shared_chirho]
    {
        shared_chirho += 1;
    }
    let mut path_chirho = PathBuf::new();
    for component_chirho in &from_components_chirho[shared_chirho..] {
        if matches!(component_chirho, Component::Normal(_)) {
            path_chirho.push("..");
        }
    }
    for component_chirho in &to_components_chirho[shared_chirho..] {
        path_chirho.push(component_chirho.as_os_str());
    }
    Ok(path_chirho)
}

fn validate_git_rev_chirho(rev_chirho: &str) -> Result<(), String> {
    let ok_chirho = rev_chirho.len() == 40
        && rev_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_hexdigit());
    if ok_chirho {
        Ok(())
    } else {
        Err(
            "sdk git rev must be a full 40-hex commit SHA, not a branch, tag, or ref name"
                .to_string(),
        )
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::check_chirho::check_app_tree_chirho;
    use crate::tree_chirho::walk_app_tree_chirho;
    use std::path::PathBuf;

    fn port_chirho(name_chirho: &str, type_chirho: &str) -> PortSpecChirho {
        PortSpecChirho {
            name_chirho: name_chirho.to_string(),
            type_chirho: type_chirho.to_string(),
        }
    }

    fn scratch_root_chirho(tag_chirho: &str) -> PathBuf {
        let root_chirho = std::env::temp_dir().join(format!(
            "tree-build-scaffold-{tag_chirho}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root_chirho);
        root_chirho
    }

    fn is_symlink_chirho(path_chirho: &Path) -> bool {
        fs::symlink_metadata(path_chirho)
            .map(|m_chirho| m_chirho.file_type().is_symlink())
            .unwrap_or(false)
    }

    #[test]
    fn scaffolds_a_wired_render_dag_chirho() {
        let root_chirho = scratch_root_chirho("render");
        let ins_chirho = vec![port_chirho("request", "http_request_v1")];
        let outs_chirho = vec![port_chirho("page", "html_partial_v1")];
        dag_new_chirho(&root_chirho, "view_x_chirho", &ins_chirho, &outs_chirho).unwrap();
        node_add_chirho(
            &root_chirho,
            "view_x_chirho",
            "render_x_chirho",
            &ins_chirho,
            &outs_chirho,
            "render_x_chirho",
        )
        .unwrap();
        wire_chirho(
            &root_chirho,
            "view_x_chirho",
            "surface:request",
            "render_x_chirho:request",
        )
        .unwrap();
        wire_chirho(
            &root_chirho,
            "view_x_chirho",
            "render_x_chirho:page",
            "surface:page",
        )
        .unwrap();

        let dag_chirho = root_chirho.join("dags_chirho/view_x_chirho");
        assert!(dag_chirho.join("spec-chirho.toml").exists());
        assert!(dag_chirho
            .join("surface_chirho/in-request-http_request_v1-chirho/.gitkeep")
            .exists());
        assert!(dag_chirho
            .join("nodes_chirho/render_x_chirho/out-page-html_partial_v1-chirho/.gitkeep")
            .exists());
        assert!(is_symlink_chirho(&dag_chirho.join(
            "nodes_chirho/render_x_chirho/in-request-http_request_v1-chirho"
        )));
        assert!(is_symlink_chirho(
            &dag_chirho.join("nodes_chirho/render_x_chirho/render_x_chirho.rs")
        ));
        assert!(is_symlink_chirho(
            &dag_chirho.join("surface_chirho/out-page-html_partial_v1-chirho")
        ));
        // the node-in wire resolves to the (existing) surface-in dir
        assert!(fs::canonicalize(
            dag_chirho.join("nodes_chirho/render_x_chirho/in-request-http_request_v1-chirho")
        )
        .is_ok());

        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn scaffolds_a_catalog_pinned_blessed_role_chirho() {
        let root_chirho = scratch_root_chirho("blessed");
        let ins_chirho = vec![port_chirho("request", "postgres_effect_request_v1")];
        let outs_chirho = vec![port_chirho("response", "effect_terminal_v1")];
        dag_new_chirho(
            &root_chirho,
            "apply_spend_chirho",
            &ins_chirho,
            &outs_chirho,
        )
        .unwrap();
        blessed_add_chirho(
            &root_chirho,
            "apply_spend_chirho",
            "commit_spend_chirho",
            &ins_chirho,
            &outs_chirho,
            &BlessedNodeSpecChirho {
                contract_chirho: "postgres-reversible",
                scope_chirho: "credits-spend-chirho",
                caller_chirho: Some("credits-demo-spend-role-chirho"),
                max_rows_chirho: None,
                max_tokens_chirho: None,
                max_price_per_token_chirho: None,
                intent_chirho: "Apply one reviewed prepaid-credit spend.",
            },
        )
        .unwrap();
        wire_chirho(
            &root_chirho,
            "apply_spend_chirho",
            "surface:request",
            "commit_spend_chirho:request",
        )
        .unwrap();
        wire_chirho(
            &root_chirho,
            "apply_spend_chirho",
            "commit_spend_chirho:response",
            "surface:response",
        )
        .unwrap();

        let tree_chirho = walk_app_tree_chirho(&root_chirho);
        let findings_chirho = check_app_tree_chirho(&tree_chirho);
        assert!(
            findings_chirho.is_empty(),
            "porcelain-authored blessed role must pass the real checker: {findings_chirho:?}"
        );
        let card_chirho = fs::read_to_string(root_chirho.join(
            "dags_chirho/apply_spend_chirho/nodes_chirho/commit_spend_chirho/blessed-contract-chirho.toml",
        ))
        .unwrap();
        assert!(card_chirho.contains("contract_chirho = \"postgres-reversible\""));
        assert!(card_chirho.contains(
            "contract_hash_chirho = \"cbc5fa7bf6c7ee7b6399d8673d3f3e5e60e27dd54851c7dc998b47a0687790c2\""
        ));
        assert!(card_chirho.contains("John 3:16"));
        assert!(!root_chirho
            .join("dags_chirho/apply_spend_chirho/nodes_chirho/commit_spend_chirho/commit_spend_chirho.rs")
            .exists());
        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn rejects_bad_port_spec_chirho() {
        assert!(parse_port_spec_chirho("no-colon").is_err());
        assert!(parse_port_spec_chirho(":type").is_err());
        assert!(parse_port_spec_chirho("name:").is_err());
        let ok_chirho = parse_port_spec_chirho("request:http_request_v1").unwrap();
        assert_eq!(ok_chirho.name_chirho, "request");
        assert_eq!(ok_chirho.type_chirho, "http_request_v1");
    }

    #[test]
    fn rejects_path_traversal_names_chirho() {
        // Author-supplied names that try to escape the app dir must fail closed before touching disk.
        assert!(parse_port_spec_chirho("../etc:passwd").is_err());
        assert!(parse_port_spec_chirho("name:ty/pe").is_err());
        let root_chirho = scratch_root_chirho("traversal");
        let ports_chirho = vec![port_chirho("request", "http_request_v1")];
        assert!(dag_new_chirho(&root_chirho, "..", &ports_chirho, &ports_chirho).is_err());
        assert!(node_add_chirho(
            &root_chirho,
            "view_x_chirho",
            "../evil",
            &ports_chirho,
            &ports_chirho,
            "x_chirho"
        )
        .is_err());
        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn new_contact_form_scaffold_checks_clean_chirho() {
        let root_chirho = scratch_root_chirho("new-contact");
        let message_chirho =
            new_app_chirho(&root_chirho, "contact-form-chirho", "path", None).unwrap();
        assert!(message_chirho.contains("tree-build-chirho check"));

        let tree_chirho = walk_app_tree_chirho(&root_chirho);
        let findings_chirho = check_app_tree_chirho(&tree_chirho);
        assert!(
            findings_chirho.is_empty(),
            "fresh scaffold should check clean: {findings_chirho:?}"
        );
        assert!(root_chirho.join("Cargo.toml").exists());
        assert!(root_chirho.join("app-chirho.toml").exists());
        assert!(root_chirho
            .join("examples/render_contact_form_guest_chirho.rs")
            .exists());
        let fixture_chirho = fs::read_to_string(
            root_chirho
                .join("fixtures_chirho/node-tests-chirho/render_contact_form_default_chirho.toml"),
        )
        .unwrap();
        let expected_chirho = fs::read(root_chirho.join(
            "fixtures_chirho/node-expected-chirho/render_contact_form_default_output_chirho.html",
        ))
        .unwrap();
        assert!(fixture_chirho.contains("tree-build-node-fixture-v1-chirho"));
        assert!(fixture_chirho.contains(&blake3::hash(&expected_chirho).to_hex().to_string()));
        let implementation_chirho = fs::read_to_string(
            root_chirho.join("src/implementations_chirho/render_contact_form_chirho.rs"),
        )
        .unwrap();
        assert!(implementation_chirho.contains("John 3:16"));
        assert!(implementation_chirho.contains("name_chirho"));

        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn new_contact_form_scaffold_git_mode_chirho() {
        let root_chirho = scratch_root_chirho("new-contact-git");
        let rev_chirho = "0123456789abcdef0123456789abcdef01234567";
        let message_chirho =
            new_app_chirho(&root_chirho, "contact-form-chirho", "git", Some(rev_chirho)).unwrap();
        assert!(message_chirho.contains("tree-build-chirho check"));
        let cargo_toml_chirho = fs::read_to_string(root_chirho.join("Cargo.toml")).unwrap();
        assert!(cargo_toml_chirho
            .contains("git = \"https://github.com/loveJesus/cairn-opensource-chirho.git\""));
        assert!(cargo_toml_chirho.contains(&format!("rev = \"{rev_chirho}\"")));
        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn new_contact_form_scaffold_git_mode_requires_safe_rev_chirho() {
        let missing_root_chirho = scratch_root_chirho("new-contact-git-missing");
        let missing_error_chirho =
            new_app_chirho(&missing_root_chirho, "contact-form-chirho", "git", None).unwrap_err();
        assert!(missing_error_chirho.contains("requires --sdk-git-rev"));
        let _ = fs::remove_dir_all(&missing_root_chirho);

        let bad_root_chirho = scratch_root_chirho("new-contact-git-bad");
        let bad_error_chirho = new_app_chirho(
            &bad_root_chirho,
            "contact-form-chirho",
            "git",
            Some("bad\"rev"),
        )
        .unwrap_err();
        assert!(bad_error_chirho.contains("sdk git rev"));
        let _ = fs::remove_dir_all(&bad_root_chirho);

        for branch_or_tag_chirho in ["main", "refs/heads/main", "v1.2.3"] {
            let named_root_chirho = scratch_root_chirho("new-contact-git-named");
            let named_error_chirho = new_app_chirho(
                &named_root_chirho,
                "contact-form-chirho",
                "git",
                Some(branch_or_tag_chirho),
            )
            .unwrap_err();
            assert!(named_error_chirho.contains("full 40-hex commit SHA"));
            let _ = fs::remove_dir_all(&named_root_chirho);
        }
    }

    #[test]
    fn new_contact_form_refuses_non_empty_dir_chirho() {
        let root_chirho = scratch_root_chirho("new-nonempty");
        create_dir_chirho(&root_chirho).unwrap();
        fs::write(root_chirho.join("existing-chirho.txt"), b"already here").unwrap();
        let error_chirho = new_app_chirho(&root_chirho, "contact-form-chirho", "path", None)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("not empty"));
        let _ = fs::remove_dir_all(&root_chirho);
    }
}
