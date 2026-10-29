// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! The checker — `dag-check`'s engine. Judges a walked app tree fail-closed and emits
//! self-contained, machine-applicable diagnostics (stable codes, expected/found/hint) so a human
//! reads kind sentences and an agent repairs in one round-trip.

use crate::emit_chirho::AppDescriptorChirho;
use crate::grammar_chirho::parse_connection_name_chirho;
use crate::tree_chirho::{
    port_schema_for_type_chirho, AppTreeChirho, DagChirho, PortChirho, PortSchemaChirho,
    PortSourceChirho, RoleBindingChirho, RoleChirho,
};
use cairn_capability_chirho::capability_spec_chirho::parse_capabilities_chirho;
use cairn_core_chirho::model_chirho::{DagChirho as CoreDagChirho, NodeDefChirho};
use cairn_core_chirho::store_chirho::hash_object_chirho;
use cairn_undo_plan_chirho::contract_chirho::canonical_authoring_reversion_contract_set_chirho;
use cairn_undo_plan_chirho::derive_chirho::{derive_undo_plan_chirho, VerifiedUndoDagInputChirho};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[path = "check_phi_chirho.rs"]
mod phi_chirho;
use phi_chirho::{port_agreement_chirho, PortAgreementChirho};

/// One check finding (same self-contained shape as a grammar diagnostic).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingChirho {
    pub code_chirho: String,
    pub where_chirho: String,
    pub message_chirho: String,
    pub expected_chirho: String,
    pub found_chirho: String,
    pub hint_chirho: String,
}

pub const CHECK_REPORT_SCHEMA_CHIRHO: &str = "tree-build-check-report-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckReportChirho {
    pub schema_chirho: String,
    pub clean_chirho: bool,
    pub finding_count_chirho: usize,
    pub findings_chirho: Vec<FindingChirho>,
}

pub fn check_report_chirho(findings_chirho: Vec<FindingChirho>) -> CheckReportChirho {
    CheckReportChirho {
        clean_chirho: findings_chirho.is_empty(),
        finding_count_chirho: findings_chirho.len(),
        findings_chirho,
        schema_chirho: CHECK_REPORT_SCHEMA_CHIRHO.to_string(),
    }
}

pub(crate) fn finding_chirho(
    code_chirho: &str,
    where_chirho: &str,
    message_chirho: &str,
    expected_chirho: &str,
    found_chirho: &str,
    hint_chirho: &str,
) -> FindingChirho {
    FindingChirho {
        code_chirho: code_chirho.to_string(),
        where_chirho: where_chirho.to_string(),
        message_chirho: message_chirho.to_string(),
        expected_chirho: expected_chirho.to_string(),
        found_chirho: found_chirho.to_string(),
        hint_chirho: hint_chirho.to_string(),
    }
}

/// Resolve a port symlink target (relative to the dir the link lives in) to an absolute path.
fn resolve_target_chirho(link_dir_chirho: &Path, target_chirho: &Path) -> PathBuf {
    if target_chirho.is_absolute() {
        target_chirho.to_path_buf()
    } else {
        link_dir_chirho.join(target_chirho)
    }
}

/// The producing out-port type named by a wire target's final path component.
fn target_out_type_chirho(target_chirho: &Path) -> Option<String> {
    let name_chirho = target_chirho.file_name()?.to_str()?;
    parse_connection_name_chirho(name_chirho)
        .ok()
        .map(|parsed_chirho| parsed_chirho.type_name_chirho)
}

fn target_out_schema_chirho(
    app_root_chirho: &Path,
    target_chirho: &Path,
) -> Option<PortSchemaChirho> {
    let producer_type_chirho = target_out_type_chirho(target_chirho)?;
    Some(port_schema_for_type_chirho(
        app_root_chirho,
        &producer_type_chirho,
    ))
}

fn schema_label_chirho(schema_chirho: &PortSchemaChirho) -> String {
    let declared_chirho = if schema_chirho.declared_chirho {
        "declared"
    } else {
        "default"
    };
    format!(
        "{} [{}] hash={}",
        schema_chirho.name_chirho, declared_chirho, schema_chirho.hash_chirho
    )
}

fn check_port_schema_chirho(
    port_label_chirho: &str,
    port_chirho: &PortChirho,
    findings_chirho: &mut Vec<FindingChirho>,
) {
    if let Some(error_chirho) = &port_chirho.schema_chirho.error_chirho {
        findings_chirho.push(finding_chirho(
            "port-schema-invalid-chirho",
            port_label_chirho,
            "this port's schema declaration is invalid",
            "a port-schema-v1-chirho file with non-empty definition_chirho",
            error_chirho,
            "fix schemas_chirho/<type>-schema-chirho.toml or remove it to use the bytes default",
        ));
    }
}

fn check_input_port_chirho(
    app_root_chirho: &Path,
    role_label_chirho: &str,
    role_dir_chirho: &Path,
    port_chirho: &PortChirho,
    findings_chirho: &mut Vec<FindingChirho>,
) {
    // Part of `spec-chirho/workflows-chirho/tree-build-typed-port-schema-check-chirho.md`.
    let port_label_chirho = format!("{role_label_chirho}/{}", port_chirho.raw_name_chirho);
    match &port_chirho.source_chirho {
        None => findings_chirho.push(finding_chirho(
            "port-unsatisfied-chirho",
            &port_label_chirho,
            "this input port has no producer",
            "exactly one producer: a wire (symlink to an out dir) XOR a pin (a dir with content_chirho.*)",
            "nothing",
            "wire it with dag-wire, or pin it with dag-pin",
        )),
        Some(PortSourceChirho::PinChirho { .. }) => {}
        Some(PortSourceChirho::WireChirho { target_chirho }) => {
            let resolved_chirho = resolve_target_chirho(role_dir_chirho, target_chirho);
            if !resolved_chirho.exists() {
                findings_chirho.push(finding_chirho(
                    "wire-dangling-chirho",
                    &port_label_chirho,
                    "this wire points at an output that does not exist",
                    "a symlink to a real out- connection dir",
                    &target_chirho.to_string_lossy(),
                    "fix the link target, or create the producing role's output",
                ));
                return;
            }
            match target_out_type_chirho(target_chirho) {
                None => findings_chirho.push(finding_chirho(
                    "wire-target-ungrammatical-chirho",
                    &port_label_chirho,
                    "the wire target is not a parseable out- connection name",
                    "out-<name>-<type>-chirho",
                    &target_chirho.to_string_lossy(),
                    "wire to a real out- connection dir",
                )),
                Some(producer_type_chirho) => {
                    let consumer_type_chirho = &port_chirho.parsed_chirho.type_name_chirho;
                    let producer_schema_chirho =
                        target_out_schema_chirho(app_root_chirho, target_chirho).unwrap_or_else(
                            || port_schema_for_type_chirho(app_root_chirho, &producer_type_chirho),
                        );
                    if let Some(error_chirho) = &producer_schema_chirho.error_chirho {
                        findings_chirho.push(finding_chirho(
                            "port-schema-invalid-chirho",
                            &port_label_chirho,
                            "the producing port's schema declaration is invalid",
                            "a port-schema-v1-chirho file with non-empty definition_chirho",
                            error_chirho,
                            "fix schemas_chirho/<type>-schema-chirho.toml or remove it to use the bytes default",
                        ));
                    }
                    match port_agreement_chirho(
                        &port_chirho.schema_chirho,
                        consumer_type_chirho,
                        &producer_schema_chirho,
                        &producer_type_chirho,
                    ) {
                        PortAgreementChirho::AgreeChirho => {}
                        PortAgreementChirho::SchemaMismatchChirho => {
                            findings_chirho.push(finding_chirho(
                                "schema-mismatch-chirho",
                                &port_label_chirho,
                                "the wire connects two different port schemas",
                                &schema_label_chirho(&port_chirho.schema_chirho),
                                &schema_label_chirho(&producer_schema_chirho),
                                "wire to an output with the same schema hash, or insert a converting role",
                            ));
                        }
                        PortAgreementChirho::TypeMismatchChirho => {
                            findings_chirho.push(finding_chirho(
                                "type-mismatch-chirho",
                                &port_label_chirho,
                                "the wire connects two different types",
                                consumer_type_chirho,
                                &producer_type_chirho,
                                "wire to an output of the matching type, or insert a converting role",
                            ));
                        }
                    }
                }
            }
        }
    }
}

fn check_role_chirho(
    app_root_chirho: &Path,
    dag_name_chirho: &str,
    role_chirho: &RoleChirho,
    findings_chirho: &mut Vec<FindingChirho>,
) {
    let role_label_chirho = format!("{dag_name_chirho}/{}", role_chirho.name_chirho);
    match &role_chirho.binding_chirho {
        RoleBindingChirho::UnboundChirho => findings_chirho.push(finding_chirho(
            "role-unbound-chirho",
            &role_label_chirho,
            "this role is bound to nothing",
            "an implementation symlink (<impl>_chirho.rs), a blessed-contract-chirho.toml card, or a builtin-phi-chirho.toml card",
            "none",
            "bind it with node-add --impl (implementation), blessed-add (blessed effect), or a builtin-phi-chirho.toml card (merge)",
        )),
        // The walker records every binding artifact it saw rather than choosing one; a role that
        // carries two is refused here so a reader of the dir never has to guess which one shipped.
        RoleBindingChirho::OverboundChirho { found_chirho } => findings_chirho.push(finding_chirho(
            "role-overbound-chirho",
            &role_label_chirho,
            "this role carries more than one binding artifact",
            "exactly one of: an implementation symlink, a blessed-contract-chirho.toml card, a builtin-phi-chirho.toml card",
            &found_chirho.join(", "),
            "remove every binding artifact but the one this role is meant to be",
        )),
        RoleBindingChirho::BuiltinPhiChirho(binding_chirho) => phi_chirho::check_phi_role_chirho(
            &role_label_chirho,
            role_chirho,
            binding_chirho.as_ref(),
            findings_chirho,
        ),
        // The impl symlink must actually resolve to a real source file — a dangling impl link is
        // the same class of bug as a dangling wire (it served the contact demo only because the
        // engine reads the manifest, not the tree links).
        RoleBindingChirho::ImplementationChirho { impl_file_chirho } => {
            let resolves_chirho = std::fs::read_link(impl_file_chirho)
                .map(|target_chirho| resolve_target_chirho(&role_chirho.dir_chirho, &target_chirho))
                .map(|resolved_chirho| resolved_chirho.exists())
                .unwrap_or(false);
            if !resolves_chirho {
                let target_chirho = std::fs::read_link(impl_file_chirho)
                    .map(|t_chirho| t_chirho.to_string_lossy().to_string())
                    .unwrap_or_else(|_e_chirho| "(not a symlink)".to_string());
                findings_chirho.push(finding_chirho(
                    "impl-dangling-chirho",
                    &role_label_chirho,
                    "the implementation symlink does not resolve to a real source file",
                    "a symlink to an existing implementation under src/",
                    &target_chirho,
                    "fix the impl link target, or create the implementation it names",
                ));
            }
        }
        // A blessed role binds a catalogued contract, not app code: resolve it against the published
        // catalog and fail closed on an unknown contract or a missing capability scope.
        RoleBindingChirho::BlessedContractChirho(binding_chirho) => {
            let binding_chirho = binding_chirho.as_ref();
            if let Err(reason_chirho) =
                crate::blessed_catalog_chirho::validate_blessed_card_v2_envelope_chirho(
                    &binding_chirho.schema_chirho,
                    &binding_chirho.intent_chirho,
                    binding_chirho.parse_error_chirho.as_deref(),
                )
            {
                findings_chirho.push(finding_chirho(
                    "blessed-card-v2-invalid-chirho",
                    &role_label_chirho,
                    "this blessed role is not a strict descriptor-v2 card",
                    "a strict blessed-card-v2-chirho document with a non-empty intent_chirho",
                    &reason_chirho,
                    "re-emit the role card from the reviewed descriptor-v2 catalog",
                ));
                return;
            }
            match crate::blessed_catalog_chirho::lookup_blessed_contract_chirho(
                &binding_chirho.contract_chirho,
            ) {
            None => findings_chirho.push(finding_chirho(
                "blessed-contract-unknown-chirho",
                &role_label_chirho,
                "this blessed role names a contract that is not in the published catalog",
                "a catalogued blessed contract (e.g. write-store, query)",
                if binding_chirho.contract_chirho.is_empty() {
                    "(none / unparsed card)"
                } else {
                    &binding_chirho.contract_chirho
                },
                "bind a catalogued contract with blessed-add; an app can request impurity, never mint it",
            )),
            Some(entry_chirho) => {
                if let Err(reason_chirho) =
                    entry_chirho.verify_contract_hash_chirho(
                        binding_chirho.contract_hash_chirho.as_deref(),
                    )
                {
                    findings_chirho.push(finding_chirho(
                        "blessed-contract-ref-invalid-chirho",
                        &role_label_chirho,
                        "this blessed role's card does not pin the published contract registry entry",
                        "contract_hash_chirho equal to the catalog entry's canonical BLAKE3 ref",
                        &reason_chirho,
                        "refresh the card with blessed-add so the blessed contract name and hash agree",
                    ));
                    return;
                }
                // The card must lower to capabilities: scope for every contract, plus caller + a positive
                // max_rows for query. Fail closed on any missing field, same as an unknown contract.
                match entry_chirho.capabilities_for_card_chirho(
                    &crate::blessed_catalog_chirho::BlessedCardParamsChirho {
                        scope_chirho: binding_chirho.scope_chirho.as_str(),
                        caller_chirho: binding_chirho.caller_chirho.as_deref(),
                        max_rows_chirho: binding_chirho.max_rows_chirho,
                        max_tokens_chirho: binding_chirho.max_tokens_chirho,
                        max_price_per_token_chirho: binding_chirho.max_price_per_token_chirho,
                    },
                ) {
                    Err(reason_chirho) => findings_chirho.push(finding_chirho(
                            "blessed-card-incomplete-chirho",
                            &role_label_chirho,
                            "this blessed role's card is missing a required capability field",
                            "a complete card (write-store: scope; query: scope + caller + positive max_rows; llm: scope + caller + positive max_tokens + positive max_price_per_token)",
                            &reason_chirho,
                            "fill the missing field in blessed-contract-chirho.toml",
                        )),
                    Ok(capability_specs_chirho) => check_canonical_reversion_resolution_chirho(
                        &role_label_chirho,
                        &capability_specs_chirho,
                        findings_chirho,
                    ),
                }
            }
            }
        }
    }
    for name_chirho in &role_chirho.malformed_connections_chirho {
        push_malformed_name_finding_chirho(&role_label_chirho, name_chirho, findings_chirho);
    }
    for port_chirho in &role_chirho.in_ports_chirho {
        let port_label_chirho = format!("{role_label_chirho}/{}", port_chirho.raw_name_chirho);
        check_port_schema_chirho(&port_label_chirho, port_chirho, findings_chirho);
        check_input_port_chirho(
            app_root_chirho,
            &role_label_chirho,
            &role_chirho.dir_chirho,
            port_chirho,
            findings_chirho,
        );
    }
    for port_chirho in &role_chirho.out_ports_chirho {
        let port_label_chirho = format!("{role_label_chirho}/{}", port_chirho.raw_name_chirho);
        check_port_schema_chirho(&port_label_chirho, port_chirho, findings_chirho);
    }
}

/// Preflights the same canonical static-undo derivation that candidate review later repeats.
///
/// Part of `spec-chirho/workflows-chirho/undo-chirho/static-undo-plan-design-chirho.md`.
fn check_canonical_reversion_resolution_chirho(
    role_label_chirho: &str,
    capability_specs_chirho: &[String],
    findings_chirho: &mut Vec<FindingChirho>,
) {
    let resolution_chirho = (|| {
        let capabilities_chirho = parse_capabilities_chirho(capability_specs_chirho)
            .map_err(|error_chirho| error_chirho.to_string())?;
        let node_def_chirho = NodeDefChirho {
            name_chirho: role_label_chirho.to_string(),
            capabilities_chirho,
            ..Default::default()
        };
        let node_hash_chirho = hash_object_chirho(&node_def_chirho)
            .map_err(|error_chirho| error_chirho.to_string())?;
        let dag_chirho = CoreDagChirho {
            nodes_chirho: vec![node_hash_chirho.clone()],
            edges_chirho: Vec::new(),
        };
        let dag_hash_chirho =
            hash_object_chirho(&dag_chirho).map_err(|error_chirho| error_chirho.to_string())?;
        derive_undo_plan_chirho(
            &VerifiedUndoDagInputChirho {
                source_dag_chirho: dag_hash_chirho,
                dag_chirho,
                node_defs_chirho: BTreeMap::from([(node_hash_chirho, node_def_chirho)]),
                pinned_config_refs_chirho: BTreeMap::new(),
            },
            &canonical_authoring_reversion_contract_set_chirho(),
        )
        .map_err(|error_chirho| error_chirho.to_string())?;
        Ok::<(), String>(())
    })();

    if let Err(reason_chirho) = resolution_chirho {
        findings_chirho.push(finding_chirho(
            "blessed-reversion-unresolved-chirho",
            role_label_chirho,
            "this blessed role's complete lowered capability set has no canonical static reversion plan",
            "every world-effect capability resolves exactly once through the current canonical reversion contract set, with every supporting capability consumed",
            &reason_chirho,
            "update the reviewed reversion contract set before emitting this blessed role; app code cannot author its own compensation semantics",
        ));
    }
}

/// Turn a dropped-by-the-walker malformed connection name into a fail-closed finding, reusing the
/// grammar parser's own diagnostic so the message/hint stay identical to a direct parse.
fn push_malformed_name_finding_chirho(
    where_chirho: &str,
    raw_name_chirho: &str,
    findings_chirho: &mut Vec<FindingChirho>,
) {
    match parse_connection_name_chirho(raw_name_chirho) {
        Ok(_parsed_chirho) => {}
        Err(grammar_error_chirho) => findings_chirho.push(finding_chirho(
            &grammar_error_chirho.code_chirho,
            where_chirho,
            &grammar_error_chirho.message_chirho,
            &grammar_error_chirho.expected_chirho,
            &grammar_error_chirho.found_chirho,
            &grammar_error_chirho.hint_chirho,
        )),
    }
}

fn check_surface_out_chirho(
    dag_chirho: &DagChirho,
    port_chirho: &PortChirho,
    findings_chirho: &mut Vec<FindingChirho>,
) {
    let label_chirho = format!(
        "{}/surface/{}",
        dag_chirho.name_chirho, port_chirho.raw_name_chirho
    );
    let surface_dir_chirho = dag_chirho.dir_chirho.join("surface_chirho");
    let link_chirho = surface_dir_chirho.join(&port_chirho.raw_name_chirho);
    let Some(target_chirho) = std::fs::read_link(&link_chirho).ok() else {
        findings_chirho.push(finding_chirho(
            "surface-out-not-a-link-chirho",
            &label_chirho,
            "a surface output must be a link to a producing role's output",
            "a symlink to an out- connection dir",
            "not a symlink",
            "link the surface output to the final role's out dir",
        ));
        return;
    };
    let resolved_chirho = resolve_target_chirho(&surface_dir_chirho, &target_chirho);
    if !resolved_chirho.exists() {
        findings_chirho.push(finding_chirho(
            "surface-out-dangling-chirho",
            &label_chirho,
            "the surface output points at an output that does not exist",
            "a symlink to a real out- connection dir",
            &target_chirho.to_string_lossy(),
            "fix the surface output link target",
        ));
    }
}

fn relative_source_label_chirho(
    root_chirho: &Path,
    path_chirho: &Path,
    line_chirho: usize,
) -> String {
    let root_canon_chirho = root_chirho
        .canonicalize()
        .unwrap_or_else(|_| root_chirho.to_path_buf());
    let path_canon_chirho = path_chirho
        .canonicalize()
        .unwrap_or_else(|_| path_chirho.to_path_buf());
    let file_chirho = path_canon_chirho
        .strip_prefix(&root_canon_chirho)
        .unwrap_or(&path_canon_chirho)
        .to_string_lossy();
    format!("{file_chirho}:{line_chirho}")
}

fn literal_asset_name_char_chirho(char_chirho: char) -> bool {
    !char_chirho.is_whitespace()
        && !matches!(
            char_chirho,
            '"' | '\'' | '`' | '<' | '>' | '(' | ')' | '?' | '#'
        )
}

fn same_app_by_name_asset_refs_chirho(
    source_chirho: &str,
    app_chirho: &str,
) -> Vec<(usize, String)> {
    let prefix_chirho = "/app-assets-chirho/";
    let mut refs_chirho = Vec::new();
    let mut search_from_chirho = 0usize;
    while let Some(offset_chirho) = source_chirho[search_from_chirho..].find(prefix_chirho) {
        let match_start_chirho = search_from_chirho + offset_chirho;
        let after_prefix_chirho = match_start_chirho + prefix_chirho.len();
        let rest_chirho = &source_chirho[after_prefix_chirho..];
        let Some(after_app_chirho) = rest_chirho.strip_prefix(app_chirho) else {
            search_from_chirho = after_prefix_chirho;
            continue;
        };
        let Some(after_by_name_chirho) = after_app_chirho.strip_prefix("/by-name-chirho/") else {
            search_from_chirho = after_prefix_chirho;
            continue;
        };
        let name_chirho: String = after_by_name_chirho
            .chars()
            .take_while(|char_chirho| literal_asset_name_char_chirho(*char_chirho))
            .collect();
        if !name_chirho.is_empty() {
            let line_chirho = source_chirho[..match_start_chirho]
                .bytes()
                .filter(|byte_chirho| *byte_chirho == b'\n')
                .count()
                + 1;
            refs_chirho.push((line_chirho, name_chirho));
        }
        search_from_chirho = after_prefix_chirho;
    }
    refs_chirho
}

fn check_literal_asset_refs_chirho(
    tree_chirho: &AppTreeChirho,
    descriptor_chirho: &AppDescriptorChirho,
    findings_chirho: &mut Vec<FindingChirho>,
) {
    let declared_chirho: BTreeSet<&str> = descriptor_chirho
        .asset_chirho
        .iter()
        .map(|asset_chirho| asset_chirho.name_chirho.as_str())
        .collect();
    for dag_chirho in &tree_chirho.dags_chirho {
        for role_chirho in &dag_chirho.roles_chirho {
            let RoleBindingChirho::ImplementationChirho { impl_file_chirho } =
                &role_chirho.binding_chirho
            else {
                continue;
            };
            let Ok(target_chirho) = std::fs::read_link(impl_file_chirho) else {
                continue;
            };
            let source_path_chirho = resolve_target_chirho(&role_chirho.dir_chirho, &target_chirho);
            let Ok(source_chirho) = std::fs::read_to_string(&source_path_chirho) else {
                continue;
            };
            for (line_chirho, name_chirho) in
                same_app_by_name_asset_refs_chirho(&source_chirho, &descriptor_chirho.app_chirho)
            {
                if declared_chirho.contains(name_chirho.as_str()) {
                    continue;
                }
                findings_chirho.push(finding_chirho(
                    "stale-asset-reference-chirho",
                    &relative_source_label_chirho(
                        &tree_chirho.root_chirho,
                        &source_path_chirho,
                        line_chirho,
                    ),
                    "this source text literally references a same-app asset name that is not declared",
                    &format!(
                        "an asset_chirho entry named '{name_chirho}' in app-chirho.toml for app '{}'",
                        descriptor_chirho.app_chirho
                    ),
                    &format!("literal by-name-chirho reference '{name_chirho}'"),
                    "declare the asset in app-chirho.toml or fix/remove the literal reference; this scan checks literal same-app /app-assets-chirho/<app>/by-name-chirho/... references in implementation source text",
                ));
            }
        }
    }
}

/// Check a whole app tree. Empty result = clean.
pub fn check_app_tree_chirho(tree_chirho: &AppTreeChirho) -> Vec<FindingChirho> {
    check_app_tree_with_descriptor_chirho(tree_chirho, None)
}

pub fn check_app_tree_with_descriptor_chirho(
    tree_chirho: &AppTreeChirho,
    descriptor_chirho: Option<&AppDescriptorChirho>,
) -> Vec<FindingChirho> {
    let mut findings_chirho = Vec::new();
    if tree_chirho.dags_chirho.is_empty() {
        findings_chirho.push(finding_chirho(
            "no-dags-chirho",
            &tree_chirho.root_chirho.to_string_lossy(),
            "no dags found under dags_chirho/",
            "at least one dag dir under dags_chirho/",
            "none",
            "add a dag with dags_chirho/<dag>/{surface_chirho,nodes_chirho}",
        ));
    }
    for dag_chirho in &tree_chirho.dags_chirho {
        for role_chirho in &dag_chirho.roles_chirho {
            check_role_chirho(
                &tree_chirho.root_chirho,
                &dag_chirho.name_chirho,
                role_chirho,
                &mut findings_chirho,
            );
        }
        for port_chirho in &dag_chirho.surface_chirho.out_ports_chirho {
            let label_chirho = format!(
                "{}/surface/{}",
                dag_chirho.name_chirho, port_chirho.raw_name_chirho
            );
            check_port_schema_chirho(&label_chirho, port_chirho, &mut findings_chirho);
            check_surface_out_chirho(dag_chirho, port_chirho, &mut findings_chirho);
        }
        for port_chirho in &dag_chirho.surface_chirho.in_ports_chirho {
            let label_chirho = format!(
                "{}/surface/{}",
                dag_chirho.name_chirho, port_chirho.raw_name_chirho
            );
            check_port_schema_chirho(&label_chirho, port_chirho, &mut findings_chirho);
        }
        let surface_label_chirho = format!("{}/surface", dag_chirho.name_chirho);
        for name_chirho in &dag_chirho.surface_chirho.malformed_connections_chirho {
            push_malformed_name_finding_chirho(
                &surface_label_chirho,
                name_chirho,
                &mut findings_chirho,
            );
        }
    }
    if let Some(descriptor_chirho) = descriptor_chirho {
        check_literal_asset_refs_chirho(tree_chirho, descriptor_chirho, &mut findings_chirho);
    }
    findings_chirho
}

#[cfg(test)]
#[path = "check_tests_chirho.rs"]
mod tests_chirho;
