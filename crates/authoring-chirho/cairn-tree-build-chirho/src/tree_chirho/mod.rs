// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Walk a directory-structure-IS-DAG app tree into a typed in-memory model: dags, their surface
//! boundary, and each role's impl/blessed binding, connection ports, and pinned content inputs.
//! Read-only and fail-soft — it records what it finds; `check_chirho` judges it.

use crate::grammar_chirho::{parse_connection_name_chirho, ConnectionNameChirho, DirectionChirho};
use serde::Deserialize;
use std::path::{Path, PathBuf};

pub const DEFAULT_PORT_SCHEMA_NAME_CHIRHO: &str = "bytes";

fn default_port_schema_hash_chirho() -> String {
    blake3::hash(DEFAULT_PORT_SCHEMA_NAME_CHIRHO.as_bytes())
        .to_hex()
        .to_string()
}

#[derive(Deserialize)]
struct PortSchemaFileChirho {
    #[serde(default)]
    schema_chirho: String,
    #[serde(default)]
    name_chirho: String,
    #[serde(default)]
    definition_chirho: String,
}

/// Check-time schema identity for one tree port. Absent declarations intentionally keep the old
/// bytes compatibility default while explicit declarations compare by BLAKE3 hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortSchemaChirho {
    pub name_chirho: String,
    pub hash_chirho: String,
    pub declared_chirho: bool,
    pub source_file_chirho: Option<PathBuf>,
    pub error_chirho: Option<String>,
}

/// How a role's input port is satisfied (per-port: exactly one, decided by `check`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortSourceChirho {
    /// A live wire: a symlink pointing at another role's (or the surface's) out connection dir.
    WireChirho { target_chirho: PathBuf },
    /// A pinned static input: a real dir holding `content_chirho.*`.
    PinChirho { content_file_chirho: PathBuf },
}

/// One connection port found in a role or the surface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortChirho {
    pub raw_name_chirho: String,
    pub dir_chirho: PathBuf,
    pub parsed_chirho: ConnectionNameChirho,
    pub schema_chirho: PortSchemaChirho,
    /// For an input port, how it is fed (None if neither wire nor pin was found).
    pub source_chirho: Option<PortSourceChirho>,
}

/// What a role's work is bound to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoleBindingChirho {
    /// A pure implementation: a symlink named `<impl>_chirho.rs` into `src/`.
    ImplementationChirho { impl_file_chirho: PathBuf },
    /// A blessed effect door: a `blessed-contract-chirho.toml` card naming a catalogued contract,
    /// pinning that contract by canonical hash, and declaring the capability scope it requests
    /// (never implementation bytes). Engine-signed registry records are the later hardening step.
    BlessedContractChirho(Box<BlessedContractBindingChirho>),
    /// A builtin phi merge: a `builtin-phi-chirho.toml` card. The role carries no implementation
    /// bytes and no capability; the engine passes exactly one live input through by hash, so a
    /// DAG can branch (one side skipped) and rejoin.
    BuiltinPhiChirho(Box<PhiBindingChirho>),
    /// More than one binding artifact in one role dir (impl link, blessed card, phi card). Recorded
    /// as found so `check` refuses instead of the walker silently preferring one of them.
    OverboundChirho { found_chirho: Vec<String> },
    /// Nothing found — `check` reports it.
    UnboundChirho,
}

pub const BLESSED_CARD_FILE_NAME_CHIRHO: &str = "blessed-contract-chirho.toml";
pub const PHI_CARD_FILE_NAME_CHIRHO: &str = "builtin-phi-chirho.toml";
pub const PHI_CARD_SCHEMA_CHIRHO: &str = "builtin-phi-v1-chirho";

/// Parsed phi card state. A parse failure is carried, never reinterpreted, so `check` and `emit`
/// both refuse the same malformed card.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhiBindingChirho {
    pub schema_chirho: String,
    pub intent_chirho: String,
    pub parse_error_chirho: Option<String>,
    pub card_file_chirho: PathBuf,
}

/// Parsed descriptor-v2 card state. This payload is boxed in `RoleBindingChirho` so the many
/// reviewed card fields do not inflate every small implementation/unbound role value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlessedContractBindingChirho {
    pub schema_chirho: String,
    pub contract_chirho: String,
    pub contract_hash_chirho: Option<String>,
    pub scope_chirho: String,
    /// Query contracts declare the metered-read caller and row cap; llm contracts declare the paid
    /// caller plus token/price ceilings; write-store leaves the contract-specific fields `None`.
    pub caller_chirho: Option<String>,
    pub max_rows_chirho: Option<u64>,
    pub max_tokens_chirho: Option<u64>,
    pub max_price_per_token_chirho: Option<i64>,
    pub intent_chirho: String,
    pub parse_error_chirho: Option<String>,
    pub card_file_chirho: PathBuf,
}

/// One role (node instance) within a dag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleChirho {
    pub name_chirho: String,
    pub dir_chirho: PathBuf,
    pub binding_chirho: RoleBindingChirho,
    pub in_ports_chirho: Vec<PortChirho>,
    pub out_ports_chirho: Vec<PortChirho>,
    /// Entries that look like connections (`in-`/`out-` prefix) but failed the grammar — kept so
    /// `check` can fail closed on a typo'd name instead of silently dropping it.
    pub malformed_connections_chirho: Vec<String>,
    pub has_spec_chirho: bool,
}

/// The dag boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SurfaceChirho {
    /// surface-ins are real dirs (the runtime lands the request stone here).
    pub in_ports_chirho: Vec<PortChirho>,
    /// surface-outs are links pointing at a producing role's out dir.
    pub out_ports_chirho: Vec<PortChirho>,
    /// `in-`/`out-`-prefixed entries that failed the grammar (surfaced by `check`).
    pub malformed_connections_chirho: Vec<String>,
}

/// One dag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DagChirho {
    pub name_chirho: String,
    pub dir_chirho: PathBuf,
    pub surface_chirho: SurfaceChirho,
    pub roles_chirho: Vec<RoleChirho>,
    pub has_spec_chirho: bool,
}

/// The whole app's dags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppTreeChirho {
    pub root_chirho: PathBuf,
    pub dags_chirho: Vec<DagChirho>,
}

fn read_link_target_chirho(path_chirho: &Path) -> Option<PathBuf> {
    std::fs::read_link(path_chirho).ok()
}

fn connection_content_file_chirho(dir_chirho: &Path) -> Option<PathBuf> {
    let entries_chirho = std::fs::read_dir(dir_chirho).ok()?;
    for entry_chirho in entries_chirho.flatten() {
        let path_chirho = entry_chirho.path();
        if path_chirho
            .file_name()
            .and_then(|name_chirho| name_chirho.to_str())
            .map(|name_chirho| name_chirho.starts_with("content_chirho."))
            .unwrap_or(false)
        {
            return Some(path_chirho);
        }
    }
    None
}

fn schema_file_for_type_chirho(app_root_chirho: &Path, type_name_chirho: &str) -> PathBuf {
    app_root_chirho
        .join("schemas_chirho")
        .join(format!("{type_name_chirho}-schema-chirho.toml"))
}

/// Part of `spec-chirho/workflows-chirho/tree-build-typed-port-schema-check-chirho.md`.
pub fn port_schema_for_type_chirho(
    app_root_chirho: &Path,
    type_name_chirho: &str,
) -> PortSchemaChirho {
    let schema_file_chirho = schema_file_for_type_chirho(app_root_chirho, type_name_chirho);
    if !schema_file_chirho.is_file() {
        return PortSchemaChirho {
            name_chirho: DEFAULT_PORT_SCHEMA_NAME_CHIRHO.to_string(),
            hash_chirho: default_port_schema_hash_chirho(),
            declared_chirho: false,
            source_file_chirho: None,
            error_chirho: None,
        };
    }

    let source_file_chirho = Some(schema_file_chirho.clone());
    let text_chirho = match std::fs::read_to_string(&schema_file_chirho) {
        Ok(text_chirho) => text_chirho,
        Err(error_chirho) => {
            return PortSchemaChirho {
                name_chirho: type_name_chirho.to_string(),
                hash_chirho: default_port_schema_hash_chirho(),
                declared_chirho: true,
                source_file_chirho,
                error_chirho: Some(format!(
                    "read {}: {error_chirho}",
                    schema_file_chirho.display()
                )),
            }
        }
    };
    let parsed_chirho = match toml::from_str::<PortSchemaFileChirho>(&text_chirho) {
        Ok(parsed_chirho) => parsed_chirho,
        Err(error_chirho) => {
            return PortSchemaChirho {
                name_chirho: type_name_chirho.to_string(),
                hash_chirho: default_port_schema_hash_chirho(),
                declared_chirho: true,
                source_file_chirho,
                error_chirho: Some(format!(
                    "parse {}: {error_chirho}",
                    schema_file_chirho.display()
                )),
            }
        }
    };
    let name_chirho = if parsed_chirho.name_chirho.trim().is_empty() {
        type_name_chirho.to_string()
    } else {
        parsed_chirho.name_chirho
    };
    let mut errors_chirho = Vec::new();
    if parsed_chirho.schema_chirho != "port-schema-v1-chirho" {
        errors_chirho.push(format!(
            "schema_chirho must be port-schema-v1-chirho, found '{}'",
            parsed_chirho.schema_chirho
        ));
    }
    if parsed_chirho.definition_chirho.trim().is_empty() {
        errors_chirho.push("definition_chirho must be non-empty".to_string());
    }
    PortSchemaChirho {
        name_chirho,
        hash_chirho: blake3::hash(parsed_chirho.definition_chirho.as_bytes())
            .to_hex()
            .to_string(),
        declared_chirho: true,
        source_file_chirho,
        error_chirho: if errors_chirho.is_empty() {
            None
        } else {
            Some(errors_chirho.join("; "))
        },
    }
}

/// Parse one connection entry (a dir or symlink whose name starts with `in-`/`out-`).
fn read_connection_port_chirho(app_root_chirho: &Path, path_chirho: &Path) -> Option<PortChirho> {
    let raw_name_chirho = path_chirho.file_name()?.to_str()?.to_string();
    if !raw_name_chirho.starts_with("in-") && !raw_name_chirho.starts_with("out-") {
        return None;
    }
    // Grammar parse may fail; record the raw name and let `check` surface the diagnostic.
    let parsed_chirho = parse_connection_name_chirho(&raw_name_chirho).ok()?;
    let is_symlink_chirho = std::fs::symlink_metadata(path_chirho)
        .map(|meta_chirho| meta_chirho.file_type().is_symlink())
        .unwrap_or(false);
    let source_chirho = if parsed_chirho.direction_chirho == DirectionChirho::InChirho {
        if is_symlink_chirho {
            read_link_target_chirho(path_chirho)
                .map(|target_chirho| PortSourceChirho::WireChirho { target_chirho })
        } else {
            connection_content_file_chirho(path_chirho).map(|content_file_chirho| {
                PortSourceChirho::PinChirho {
                    content_file_chirho,
                }
            })
        }
    } else {
        None
    };
    Some(PortChirho {
        raw_name_chirho,
        dir_chirho: path_chirho.to_path_buf(),
        schema_chirho: port_schema_for_type_chirho(
            app_root_chirho,
            &parsed_chirho.type_name_chirho,
        ),
        parsed_chirho,
        source_chirho,
    })
}

fn looks_like_connection_chirho(name_chirho: &str) -> bool {
    name_chirho.starts_with("in-") || name_chirho.starts_with("out-")
}

/// Returns (in ports, out ports, malformed connection names). An entry whose name has an
/// `in-`/`out-` prefix but fails the grammar is recorded as malformed — never silently dropped.
fn read_ports_chirho(
    app_root_chirho: &Path,
    dir_chirho: &Path,
) -> (Vec<PortChirho>, Vec<PortChirho>, Vec<String>) {
    let mut ins_chirho = Vec::new();
    let mut outs_chirho = Vec::new();
    let mut malformed_chirho = Vec::new();
    if let Ok(entries_chirho) = std::fs::read_dir(dir_chirho) {
        for entry_chirho in entries_chirho.flatten() {
            let path_chirho = entry_chirho.path();
            match read_connection_port_chirho(app_root_chirho, &path_chirho) {
                Some(port_chirho) => match port_chirho.parsed_chirho.direction_chirho {
                    DirectionChirho::InChirho => ins_chirho.push(port_chirho),
                    DirectionChirho::OutChirho => outs_chirho.push(port_chirho),
                },
                None => {
                    if let Some(name_chirho) = path_chirho
                        .file_name()
                        .and_then(|n_chirho| n_chirho.to_str())
                    {
                        if looks_like_connection_chirho(name_chirho)
                            && parse_connection_name_chirho(name_chirho).is_err()
                        {
                            malformed_chirho.push(name_chirho.to_string());
                        }
                    }
                }
            }
        }
    }
    ins_chirho
        .sort_by(|a_chirho, b_chirho| a_chirho.raw_name_chirho.cmp(&b_chirho.raw_name_chirho));
    outs_chirho
        .sort_by(|a_chirho, b_chirho| a_chirho.raw_name_chirho.cmp(&b_chirho.raw_name_chirho));
    malformed_chirho.sort();
    (ins_chirho, outs_chirho, malformed_chirho)
}

/// The blessed card (`blessed-contract-chirho.toml`): names a catalogued contract and the capability
/// scope it requests. The v2 hard break is strict: missing or unknown fields make parsing fail, and
/// the parse error is carried to `check`/`emit` so neither path can reinterpret a malformed card.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlessedCardChirho {
    schema_chirho: String,
    contract_chirho: String,
    contract_hash_chirho: Option<String>,
    scope_chirho: String,
    caller_chirho: Option<String>,
    max_rows_chirho: Option<u64>,
    max_tokens_chirho: Option<u64>,
    max_price_per_token_chirho: Option<i64>,
    intent_chirho: String,
}

/// The phi card (`builtin-phi-chirho.toml`): a schema line and the author's intent. Strict for the
/// same reason as the blessed card — an unknown field is a typo the author must see.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PhiCardChirho {
    schema_chirho: String,
    intent_chirho: String,
}

fn read_blessed_binding_chirho(card_chirho: PathBuf) -> RoleBindingChirho {
    let parsed_chirho = std::fs::read_to_string(&card_chirho)
        .map_err(|error_chirho| format!("read blessed card: {error_chirho}"))
        .and_then(|text_chirho| {
            toml::from_str::<BlessedCardChirho>(&text_chirho)
                .map_err(|error_chirho| format!("parse blessed card v2: {error_chirho}"))
        });
    match parsed_chirho {
        Ok(parsed_chirho) => {
            RoleBindingChirho::BlessedContractChirho(Box::new(BlessedContractBindingChirho {
                schema_chirho: parsed_chirho.schema_chirho,
                contract_chirho: parsed_chirho.contract_chirho,
                contract_hash_chirho: parsed_chirho.contract_hash_chirho,
                scope_chirho: parsed_chirho.scope_chirho,
                caller_chirho: parsed_chirho.caller_chirho,
                max_rows_chirho: parsed_chirho.max_rows_chirho,
                max_tokens_chirho: parsed_chirho.max_tokens_chirho,
                max_price_per_token_chirho: parsed_chirho.max_price_per_token_chirho,
                intent_chirho: parsed_chirho.intent_chirho,
                parse_error_chirho: None,
                card_file_chirho: card_chirho,
            }))
        }
        Err(error_chirho) => {
            RoleBindingChirho::BlessedContractChirho(Box::new(BlessedContractBindingChirho {
                schema_chirho: String::new(),
                contract_chirho: String::new(),
                contract_hash_chirho: None,
                scope_chirho: String::new(),
                caller_chirho: None,
                max_rows_chirho: None,
                max_tokens_chirho: None,
                max_price_per_token_chirho: None,
                intent_chirho: String::new(),
                parse_error_chirho: Some(error_chirho),
                card_file_chirho: card_chirho,
            }))
        }
    }
}

fn read_phi_binding_chirho(card_chirho: PathBuf) -> RoleBindingChirho {
    let parsed_chirho = std::fs::read_to_string(&card_chirho)
        .map_err(|error_chirho| format!("read phi card: {error_chirho}"))
        .and_then(|text_chirho| {
            toml::from_str::<PhiCardChirho>(&text_chirho)
                .map_err(|error_chirho| format!("parse phi card: {error_chirho}"))
        });
    match parsed_chirho {
        Ok(parsed_chirho) => RoleBindingChirho::BuiltinPhiChirho(Box::new(PhiBindingChirho {
            schema_chirho: parsed_chirho.schema_chirho,
            intent_chirho: parsed_chirho.intent_chirho,
            parse_error_chirho: None,
            card_file_chirho: card_chirho,
        })),
        Err(error_chirho) => RoleBindingChirho::BuiltinPhiChirho(Box::new(PhiBindingChirho {
            schema_chirho: String::new(),
            intent_chirho: String::new(),
            parse_error_chirho: Some(error_chirho),
            card_file_chirho: card_chirho,
        })),
    }
}

/// A role binds exactly one of: an impl symlink, a blessed card, a phi card. Every artifact
/// present is collected first, so two of them together become `OverboundChirho` (named, sorted)
/// rather than a silent preference — the reader of a role dir must never have to guess which
/// artifact the toolchain honoured.
fn read_role_binding_chirho(dir_chirho: &Path) -> RoleBindingChirho {
    let mut found_chirho: Vec<String> = Vec::new();
    let mut binding_chirho = RoleBindingChirho::UnboundChirho;
    let blessed_card_chirho = dir_chirho.join(BLESSED_CARD_FILE_NAME_CHIRHO);
    if blessed_card_chirho.is_file() {
        found_chirho.push(BLESSED_CARD_FILE_NAME_CHIRHO.to_string());
        binding_chirho = read_blessed_binding_chirho(blessed_card_chirho);
    }
    let phi_card_chirho = dir_chirho.join(PHI_CARD_FILE_NAME_CHIRHO);
    if phi_card_chirho.is_file() {
        found_chirho.push(PHI_CARD_FILE_NAME_CHIRHO.to_string());
        binding_chirho = read_phi_binding_chirho(phi_card_chirho);
    }
    if let Ok(entries_chirho) = std::fs::read_dir(dir_chirho) {
        for entry_chirho in entries_chirho.flatten() {
            let path_chirho = entry_chirho.path();
            let name_chirho = entry_chirho.file_name().to_string_lossy().to_string();
            let is_symlink_chirho = std::fs::symlink_metadata(&path_chirho)
                .map(|meta_chirho| meta_chirho.file_type().is_symlink())
                .unwrap_or(false);
            if is_symlink_chirho && name_chirho.ends_with("_chirho.rs") {
                found_chirho.push(name_chirho);
                binding_chirho = RoleBindingChirho::ImplementationChirho {
                    impl_file_chirho: path_chirho,
                };
            }
        }
    }
    if found_chirho.len() > 1 {
        found_chirho.sort();
        return RoleBindingChirho::OverboundChirho { found_chirho };
    }
    binding_chirho
}

/// The engine-side name of a role's output port. v0 lowers every implementation and blessed role to
/// one `out`; a phi role's output port is the `<name>` segment of its single `out-` connection.
pub fn role_output_port_name_chirho(role_chirho: &RoleChirho) -> String {
    match &role_chirho.binding_chirho {
        RoleBindingChirho::BuiltinPhiChirho(_) => match role_chirho.out_ports_chirho.as_slice() {
            [port_chirho] => port_chirho.parsed_chirho.name_chirho.clone(),
            _ => "out".to_string(),
        },
        _ => "out".to_string(),
    }
}

/// The engine-side name of one of a role's input ports: `in` for every v0 single-port role, the
/// connection's `<name>` segment for a phi (whose ports are distinct by construction).
pub fn role_input_port_name_chirho(role_chirho: &RoleChirho, port_chirho: &PortChirho) -> String {
    match &role_chirho.binding_chirho {
        RoleBindingChirho::BuiltinPhiChirho(_) => port_chirho.parsed_chirho.name_chirho.clone(),
        _ => "in".to_string(),
    }
}

fn read_role_chirho(app_root_chirho: &Path, dir_chirho: &Path) -> Option<RoleChirho> {
    let name_chirho = dir_chirho.file_name()?.to_str()?.to_string();
    let (in_ports_chirho, out_ports_chirho, malformed_connections_chirho) =
        read_ports_chirho(app_root_chirho, dir_chirho);
    Some(RoleChirho {
        name_chirho,
        binding_chirho: read_role_binding_chirho(dir_chirho),
        in_ports_chirho,
        out_ports_chirho,
        malformed_connections_chirho,
        has_spec_chirho: dir_chirho.join("spec-chirho.toml").is_file(),
        dir_chirho: dir_chirho.to_path_buf(),
    })
}

fn sorted_subdirs_chirho(dir_chirho: &Path) -> Vec<PathBuf> {
    let mut dirs_chirho = Vec::new();
    if let Ok(entries_chirho) = std::fs::read_dir(dir_chirho) {
        for entry_chirho in entries_chirho.flatten() {
            if entry_chirho.path().is_dir() {
                dirs_chirho.push(entry_chirho.path());
            }
        }
    }
    dirs_chirho.sort();
    dirs_chirho
}

fn read_dag_chirho(app_root_chirho: &Path, dir_chirho: &Path) -> Option<DagChirho> {
    let name_chirho = dir_chirho.file_name()?.to_str()?.to_string();
    let surface_dir_chirho = dir_chirho.join("surface_chirho");
    let (surface_in_chirho, surface_out_chirho, surface_malformed_chirho) =
        read_ports_chirho(app_root_chirho, &surface_dir_chirho);
    let roles_dir_chirho = dir_chirho.join("nodes_chirho");
    let roles_chirho = sorted_subdirs_chirho(&roles_dir_chirho)
        .iter()
        .filter_map(|role_dir_chirho| read_role_chirho(app_root_chirho, role_dir_chirho))
        .collect();
    Some(DagChirho {
        name_chirho,
        surface_chirho: SurfaceChirho {
            in_ports_chirho: surface_in_chirho,
            out_ports_chirho: surface_out_chirho,
            malformed_connections_chirho: surface_malformed_chirho,
        },
        roles_chirho,
        has_spec_chirho: dir_chirho.join("spec-chirho.toml").is_file(),
        dir_chirho: dir_chirho.to_path_buf(),
    })
}

/// Walk an app tree rooted at `app_root` (the dir holding `dags_chirho/`).
pub fn walk_app_tree_chirho(app_root_chirho: &Path) -> AppTreeChirho {
    let dags_root_chirho = app_root_chirho.join("dags_chirho");
    let dags_chirho = sorted_subdirs_chirho(&dags_root_chirho)
        .iter()
        .filter_map(|dag_dir_chirho| read_dag_chirho(app_root_chirho, dag_dir_chirho))
        .collect();
    AppTreeChirho {
        root_chirho: app_root_chirho.to_path_buf(),
        dags_chirho,
    }
}

#[cfg(test)]
#[path = "tests_chirho.rs"]
mod tests_chirho;
