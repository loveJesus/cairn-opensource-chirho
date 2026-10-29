// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Emit an app-source manifest from the dag tree + the app descriptor. v0 lowering conventions
//! (named here, not hidden): each role -> one single-port node whose wasm guest is
//! `<id>_guest_chirho`; the role's single live wire -> the node's `in`; pins are baked into the
//! guest; dag/module/route ids derive by convention; protocol route labels come from the app
//! descriptor (per the "surface is not routes" doctrine). The result is deploy-identical to the
//! hand-proven manifest (golden test). The one multi-port role is the builtin phi: its ports are
//! the `<name>` segments of its in-/out- connections, so edges into and out of it name those ports.

use crate::blessed_catalog_chirho;
use crate::grammar_chirho::DirectionChirho;
use crate::tree_chirho::{
    role_input_port_name_chirho, role_output_port_name_chirho, AppTreeChirho, DagChirho,
    PortSourceChirho, RoleBindingChirho, RoleChirho, PHI_CARD_SCHEMA_CHIRHO,
};
use cairn_core_chirho::model_chirho::BUILTIN_PHI_ENTRY_CHIRHO;
use cairn_model_app_chirho::{
    AppRequestAccessPolicyChirho, AppRouteKeyAccessChirho, AppRouteRequestBodyPolicyChirho,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

/// Every app route currently renders an HTML partial, so emit declares `text/html` by default — the
/// metadata the engine needs to send `Content-Type: text/html` rather than a download. A per-route
/// override in the app descriptor (e.g. a JSON API route) is the follow-on.
const DEFAULT_RESPONSE_CONTENT_TYPE_CHIRHO: &str = "text/html";

/// The app-level descriptor (`app-chirho.toml`) — the things above the dag.
#[derive(Clone, Debug, Deserialize)]
pub struct AppDescriptorChirho {
    pub app_chirho: String,
    pub owner_chirho: String,
    pub package_chirho: String,
    /// App-wide request admission, checked before route lookup, body handling, or DAG execution.
    #[serde(default)]
    pub request_access_policy_chirho: Option<String>,
    pub root_chirho: AppRootChirho,
    /// Additional pages served as named routes alongside the root (e.g. the order page).
    #[serde(default)]
    pub route_chirho: Vec<AppRouteChirho>,
    /// DAG modules included in the source manifest but not deployed as public routes.
    #[serde(default)]
    pub internal_module_chirho: Vec<AppInternalModuleChirho>,
    /// Static assets deployed with the app. The runtime enforces the reviewed MIME allowlist.
    #[serde(default)]
    pub asset_chirho: Vec<AppAssetChirho>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AppRootChirho {
    pub dag_chirho: String,
    pub input_mode_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_chirho: Option<String>,
    #[serde(default)]
    pub safe_metadata_chirho: Vec<AppSafeMetadataChirho>,
    #[serde(default)]
    pub request_body_policy_chirho: Option<String>,
    pub route_label_chirho: String,
    /// Read only to refuse it: the app root is never opened to limited keys, so declaring it is an error rather than
    /// a silently ignored line.
    #[serde(default)]
    pub key_access_chirho: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AppRouteChirho {
    pub dag_chirho: String,
    pub input_mode_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_chirho: Option<String>,
    #[serde(default)]
    pub safe_metadata_chirho: Vec<AppSafeMetadataChirho>,
    #[serde(default)]
    pub request_body_policy_chirho: Option<String>,
    pub route_chirho: String,
    /// `"open"` opens this route to limited keys holding a grant for `key_action_chirho` (K1). Both or neither.
    #[serde(default)]
    pub key_access_chirho: Option<String>,
    #[serde(default)]
    pub key_action_chirho: Option<String>,
    /// The logical viewer-state keys a limited key may touch through this route.
    #[serde(default)]
    pub key_resources_chirho: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AppSafeMetadataChirho {
    pub key_chirho: String,
    pub allowed_values_chirho: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AppInternalModuleChirho {
    pub dag_chirho: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AppAssetChirho {
    pub name_chirho: String,
    pub path_chirho: String,
    pub content_type_chirho: String,
}

// ---- manifest shape (subset we emit), serializing to the app-source-manifest-v1 keys ----

#[derive(Serialize)]
struct ManifestChirho {
    schema_chirho: String,
    app_chirho: String,
    owner_chirho: String,
    nodes_chirho: Vec<NodeChirho>,
    dags_chirho: Vec<DagOutChirho>,
    modules_chirho: Vec<ModuleChirho>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    assets_chirho: Vec<AssetChirho>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    contract_refs_chirho: Vec<String>,
    deploy_chirho: DeployChirho,
}

#[derive(Serialize)]
struct NodeChirho {
    id_chirho: String,
    name_chirho: String,
    entry_chirho: String,
    fuel_chirho: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    capabilities_chirho: Vec<String>,
    source_chirho: NodeSourceChirho,
}

#[derive(Serialize)]
struct AssetChirho {
    name_chirho: String,
    content_type_chirho: String,
    source_chirho: AssetSourceChirho,
}

#[derive(Serialize)]
#[serde(tag = "kind_chirho", rename_all = "kebab-case")]
enum AssetSourceChirho {
    PathChirho { path_chirho: String },
}

/// A node's wasm source, serialized to the app-source-manifest `source_chirho` shape. A pure role
/// lowers to its cargo-example guest; a blessed role lowers to the engine's built-in inert template
/// wasm (the capability, not the wasm body, does the work); a phi role lowers to the engine's
/// builtin merge, which has no wasm at all.
#[derive(Serialize)]
#[serde(tag = "kind_chirho", rename_all = "kebab-case")]
enum NodeSourceChirho {
    BuiltinNodeTemplateChirho {
        template_chirho: String,
    },
    CargoExampleChirho {
        package_chirho: String,
        example_chirho: String,
        features_chirho: Vec<String>,
        manifest_path_chirho: String,
        artifact_path_chirho: String,
    },
    BuiltinPhiChirho {
        input_ports_chirho: Vec<String>,
        output_port_chirho: String,
    },
}

#[derive(Serialize)]
struct DagOutChirho {
    id_chirho: String,
    nodes_chirho: Vec<String>,
    edges_chirho: Vec<EdgeChirho>,
}

#[derive(Serialize)]
struct EdgeChirho {
    from_node_chirho: String,
    from_port_chirho: String,
    to_node_chirho: String,
    to_port_chirho: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    privacy_chirho: Option<EdgePrivacyChirho>,
}

#[derive(Serialize, Clone)]
#[serde(tag = "kind_chirho", rename_all = "kebab-case")]
enum EdgePrivacyChirho {
    PrivateBlobRefChirho {
        subject_source_chirho: EdgePrivacySubjectSourceChirho,
    },
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "kebab-case")]
enum EdgePrivacySubjectSourceChirho {
    RequestUserChirho,
}

#[derive(Serialize)]
struct ModuleChirho {
    id_chirho: String,
    dag_chirho: String,
    name_chirho: String,
    version_chirho: String,
    input_bindings_chirho: Vec<BindingChirho>,
    output_bindings_chirho: Vec<BindingChirho>,
    route_labels_chirho: Vec<String>,
}

#[derive(Serialize)]
struct BindingChirho {
    public_name_chirho: String,
    node_chirho: String,
    node_port_chirho: String,
}

#[derive(Serialize)]
struct DeployChirho {
    root_chirho: DeployRootChirho,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_access_policy_chirho: Option<AppRequestAccessPolicyChirho>,
    input_mode_chirho: InputModeChirho,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_body_policy_chirho: Option<AppRouteRequestBodyPolicyChirho>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    routes_chirho: Vec<DeployRouteChirho>,
    target_chirho: TargetChirho,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_content_type_chirho: Option<String>,
}

#[derive(Serialize)]
struct DeployRouteChirho {
    route_chirho: String,
    source_chirho: DeployRootChirho,
    input_mode_chirho: InputModeChirho,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_body_policy_chirho: Option<AppRouteRequestBodyPolicyChirho>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_access_chirho: Option<AppRouteKeyAccessChirho>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_content_type_chirho: Option<String>,
}

#[derive(Serialize)]
struct DeployRootChirho {
    kind_chirho: String,
    id_chirho: String,
}

#[derive(Serialize)]
struct InputModeChirho {
    kind_chirho: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject_chirho: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    safe_metadata_chirho: Vec<AppSafeMetadataChirho>,
}

#[derive(Serialize)]
struct TargetChirho {
    kind_chirho: String,
}

fn strip_chirho_suffix_chirho(name_chirho: &str) -> String {
    name_chirho
        .strip_suffix("_chirho")
        .unwrap_or(name_chirho)
        .to_string()
}

fn input_mode_chirho(
    kind_chirho: &str,
    subject_chirho: Option<&str>,
    safe_metadata_chirho: &[AppSafeMetadataChirho],
) -> Result<InputModeChirho, String> {
    let emitted_kind_chirho = format!("{kind_chirho}-chirho");
    let private_chirho = emitted_kind_chirho == "private-blob-ref-chirho";
    let subject_chirho = subject_chirho.map(str::to_string);
    if private_chirho && subject_chirho.as_deref().unwrap_or("").trim().is_empty() {
        return Err("private-blob-ref input mode requires subject_chirho".to_string());
    }
    if !private_chirho && subject_chirho.is_some() {
        return Err(format!(
            "input mode '{kind_chirho}' must not declare subject_chirho"
        ));
    }
    if !private_chirho && !safe_metadata_chirho.is_empty() {
        return Err(format!(
            "input mode '{kind_chirho}' must not declare safe_metadata_chirho"
        ));
    }
    Ok(InputModeChirho {
        kind_chirho: emitted_kind_chirho,
        subject_chirho,
        safe_metadata_chirho: safe_metadata_chirho.to_vec(),
    })
}

/// Lower the author-facing root or named-route policy into the signed source-manifest shape consumed by the
/// deployment workflow in `spec-chirho/workflows-chirho/app-route-request-body-policy-chirho.md`.
fn request_body_policy_chirho(
    policy_chirho: Option<&str>,
) -> Result<Option<AppRouteRequestBodyPolicyChirho>, String> {
    match policy_chirho {
        None => Ok(None),
        Some("accept-body") => Ok(Some(
            AppRouteRequestBodyPolicyChirho::AcceptBodyChirho,
        )),
        Some("no-body") => Ok(Some(AppRouteRequestBodyPolicyChirho::NoBodyChirho)),
        Some(policy_chirho) => Err(format!(
            "unknown request_body_policy_chirho '{policy_chirho}'; expected 'accept-body' or 'no-body'"
        )),
    }
}

/// Lower a named route's opening to limited keys into the source-manifest shape: `key_access_chirho = "open"` and
/// `key_action_chirho` together or not at all, and `key_resources_chirho` only with them. Deploy then checks the action
/// and resource grammar and that every capability of the route's DAG is one a key may reach.
/// Workflow: limited-key authority (K1),
/// `spec-chirho/workflows-chirho/identity-auth-chirho/limited-key-authority-chirho.md`.
fn key_access_chirho(
    route_chirho: &AppRouteChirho,
) -> Result<Option<AppRouteKeyAccessChirho>, String> {
    let route_name_chirho = &route_chirho.route_chirho;
    match (
        route_chirho.key_access_chirho.as_deref(),
        route_chirho.key_action_chirho.as_deref(),
    ) {
        (None, None) if route_chirho.key_resources_chirho.is_empty() => Ok(None),
        (None, None) => Err(format!(
            "route '{route_name_chirho}': key_resources_chirho needs key_access_chirho = \"open\""
        )),
        (Some("open"), Some(action_chirho)) => Ok(Some(AppRouteKeyAccessChirho::OpenChirho {
            action_chirho: action_chirho.to_string(),
            resources_chirho: route_chirho.key_resources_chirho.clone(),
        })),
        (Some("open"), None) => Err(format!(
            "route '{route_name_chirho}': key_access_chirho = \"open\" needs key_action_chirho"
        )),
        (None, Some(_)) => Err(format!(
            "route '{route_name_chirho}': key_action_chirho needs key_access_chirho = \"open\""
        )),
        (Some(other_chirho), _) => Err(format!(
            "route '{route_name_chirho}': unknown key_access_chirho '{other_chirho}'; expected 'open'"
        )),
    }
}

fn request_access_policy_chirho(
    policy_chirho: Option<&str>,
) -> Result<Option<AppRequestAccessPolicyChirho>, String> {
    match policy_chirho {
        None => Ok(None),
        Some("public") => Ok(Some(AppRequestAccessPolicyChirho::PublicChirho)),
        Some("authenticated") => Ok(Some(
            AppRequestAccessPolicyChirho::AuthenticatedChirho,
        )),
        Some(policy_chirho) => Err(format!(
            "unknown request_access_policy_chirho '{policy_chirho}'; expected 'public' or 'authenticated'"
        )),
    }
}

/// The role-dir name a wire target points into (its parent component).
fn wire_producer_role_chirho(target_chirho: &Path) -> Option<String> {
    target_chirho
        .parent()
        .and_then(|p_chirho| p_chirho.file_name())
        .and_then(|n_chirho| n_chirho.to_str())
        .map(|n_chirho| n_chirho.to_string())
}

/// Is this wire fed from the dag surface (vs another role)?
fn wire_from_surface_chirho(target_chirho: &Path) -> bool {
    wire_producer_role_chirho(target_chirho).as_deref() == Some("surface_chirho")
}

fn private_edge_for_port_chirho(
    port_chirho: &crate::tree_chirho::PortChirho,
) -> Option<EdgePrivacyChirho> {
    let marker_chirho = port_chirho.dir_chirho.join("private-edge-chirho.toml");
    if marker_chirho.is_file() {
        return Some(EdgePrivacyChirho::PrivateBlobRefChirho {
            subject_source_chirho: EdgePrivacySubjectSourceChirho::RequestUserChirho,
        });
    }
    None
}

fn blessed_contract_refs_chirho(
    tree_chirho: &AppTreeChirho,
    nodes_chirho: &[NodeChirho],
) -> Vec<String> {
    let emitted_ids_chirho = nodes_chirho
        .iter()
        .map(|node_chirho| node_chirho.id_chirho.as_str())
        .collect::<BTreeSet<_>>();
    let mut refs_chirho = Vec::new();
    for dag_chirho in &tree_chirho.dags_chirho {
        for role_chirho in &dag_chirho.roles_chirho {
            let role_id_chirho = strip_chirho_suffix_chirho(&role_chirho.name_chirho);
            if !emitted_ids_chirho.contains(role_id_chirho.as_str()) {
                continue;
            }
            if let RoleBindingChirho::BlessedContractChirho(binding_chirho) =
                &role_chirho.binding_chirho
            {
                let Some(contract_hash_chirho) = &binding_chirho.contract_hash_chirho else {
                    continue;
                };
                let ref_chirho = format!("blessed-contract:{contract_hash_chirho}");
                if !refs_chirho.contains(&ref_chirho) {
                    refs_chirho.push(ref_chirho);
                }
            }
        }
    }
    refs_chirho.sort();
    refs_chirho
}

fn node_for_role_chirho(
    role_chirho: &RoleChirho,
    descriptor_chirho: &AppDescriptorChirho,
) -> Result<NodeChirho, String> {
    let id_chirho = strip_chirho_suffix_chirho(&role_chirho.name_chirho);
    // A blessed role lowers to the shared inert template wasm + the catalogued capability; the
    // builder fails closed if the named contract is not in the published catalog.
    if let RoleBindingChirho::BlessedContractChirho(binding_chirho) = &role_chirho.binding_chirho {
        let binding_chirho = binding_chirho.as_ref();
        blessed_catalog_chirho::validate_blessed_card_v2_envelope_chirho(
            &binding_chirho.schema_chirho,
            &binding_chirho.intent_chirho,
            binding_chirho.parse_error_chirho.as_deref(),
        )
        .map_err(|reason_chirho| {
            format!(
                "role '{}' blessed card v2: {reason_chirho}",
                role_chirho.name_chirho
            )
        })?;
        let entry_chirho = blessed_catalog_chirho::resolve_blessed_contract_chirho(
            &binding_chirho.contract_chirho,
            binding_chirho.contract_hash_chirho.as_deref(),
        )
        .map_err(|reason_chirho| {
            format!(
                "role '{}' blessed contract ref: {reason_chirho}",
                role_chirho.name_chirho
            )
        })?;
        let capabilities_chirho = entry_chirho
            .capabilities_for_card_chirho(&blessed_catalog_chirho::BlessedCardParamsChirho {
                scope_chirho: binding_chirho.scope_chirho.as_str(),
                caller_chirho: binding_chirho.caller_chirho.as_deref(),
                max_rows_chirho: binding_chirho.max_rows_chirho,
                max_tokens_chirho: binding_chirho.max_tokens_chirho,
                max_price_per_token_chirho: binding_chirho.max_price_per_token_chirho,
            })
            .map_err(|reason_chirho| {
                format!(
                    "role '{}' blessed card: {reason_chirho}",
                    role_chirho.name_chirho
                )
            })?;
        return Ok(NodeChirho {
            id_chirho,
            name_chirho: role_chirho.name_chirho.clone(),
            entry_chirho: entry_chirho.entry_chirho.to_string(),
            fuel_chirho: entry_chirho.fuel_chirho,
            capabilities_chirho,
            source_chirho: NodeSourceChirho::BuiltinNodeTemplateChirho {
                template_chirho: "node-template-chirho".to_string(),
            },
        });
    }
    // A phi role lowers to the engine's builtin merge: no wasm, no fuel, no capability; its
    // ports are the connection names, in the walker's (sorted) order.
    if let RoleBindingChirho::BuiltinPhiChirho(binding_chirho) = &role_chirho.binding_chirho {
        if let Some(error_chirho) = &binding_chirho.parse_error_chirho {
            return Err(format!(
                "role '{}' phi card: {error_chirho}",
                role_chirho.name_chirho
            ));
        }
        if binding_chirho.schema_chirho != PHI_CARD_SCHEMA_CHIRHO
            || binding_chirho.intent_chirho.trim().is_empty()
        {
            return Err(format!(
                "role '{}' phi card must declare schema_chirho = {PHI_CARD_SCHEMA_CHIRHO} and a non-empty intent_chirho",
                role_chirho.name_chirho
            ));
        }
        if role_chirho.in_ports_chirho.len() < 2 || role_chirho.out_ports_chirho.len() != 1 {
            return Err(format!(
                "role '{}' phi needs at least two in- connections and exactly one out- connection; found {} and {}",
                role_chirho.name_chirho,
                role_chirho.in_ports_chirho.len(),
                role_chirho.out_ports_chirho.len()
            ));
        }
        return Ok(NodeChirho {
            id_chirho,
            name_chirho: role_chirho.name_chirho.clone(),
            entry_chirho: BUILTIN_PHI_ENTRY_CHIRHO.to_string(),
            fuel_chirho: 0,
            capabilities_chirho: vec![],
            source_chirho: NodeSourceChirho::BuiltinPhiChirho {
                input_ports_chirho: role_chirho
                    .in_ports_chirho
                    .iter()
                    .map(|port_chirho| role_input_port_name_chirho(role_chirho, port_chirho))
                    .collect(),
                output_port_chirho: role_output_port_name_chirho(role_chirho),
            },
        });
    }
    if let RoleBindingChirho::OverboundChirho { found_chirho } = &role_chirho.binding_chirho {
        return Err(format!(
            "role '{}' carries more than one binding artifact: {}",
            role_chirho.name_chirho,
            found_chirho.join(", ")
        ));
    }
    // A pure implementation role lowers to its cargo-example guest.
    let example_chirho = format!("{id_chirho}_guest_chirho");
    Ok(NodeChirho {
        id_chirho,
        name_chirho: role_chirho.name_chirho.clone(),
        entry_chirho: role_chirho.name_chirho.clone(),
        fuel_chirho: 50_000_000,
        capabilities_chirho: vec![],
        source_chirho: NodeSourceChirho::CargoExampleChirho {
            package_chirho: descriptor_chirho.package_chirho.clone(),
            example_chirho: example_chirho.clone(),
            features_chirho: vec![],
            manifest_path_chirho: "Cargo.toml".to_string(),
            artifact_path_chirho: format!(
                "target/wasm32-unknown-unknown/debug/examples/{example_chirho}.wasm"
            ),
        },
    })
}

/// What one dag lowers to: its nodes, the dag object, and its module (+ id for deploy wiring).
struct LoweredDagChirho {
    nodes_chirho: Vec<NodeChirho>,
    dag_chirho: DagOutChirho,
    module_chirho: ModuleChirho,
    module_id_chirho: String,
}

/// Lower one dag (found by name) into its nodes + dag + module. `route_labels_chirho` are supplied
/// by the app descriptor for deployable routes; internal modules deliberately carry no route labels.
fn lower_dag_chirho(
    tree_chirho: &AppTreeChirho,
    descriptor_chirho: &AppDescriptorChirho,
    dag_name_chirho: &str,
    route_labels_chirho: Vec<String>,
) -> Result<LoweredDagChirho, String> {
    let dag_chirho = tree_chirho
        .dags_chirho
        .iter()
        .find(|d_chirho| d_chirho.name_chirho == dag_name_chirho)
        .ok_or_else(|| {
            format!("app descriptor names dag '{dag_name_chirho}' but the tree has no such dag")
        })?;

    let nodes_chirho: Vec<NodeChirho> = dag_chirho
        .roles_chirho
        .iter()
        .map(|role_chirho| node_for_role_chirho(role_chirho, descriptor_chirho))
        .collect::<Result<Vec<_>, _>>()?;

    // Edges: each role's live wire from ANOTHER role -> one edge, named by the producer's output
    // port and the consumer's input port (`out`/`in` for v0 single-port roles, the connection
    // `<name>` for a phi). The executor feeds the request to EVERY role with no incoming edge, so
    // more than one role may be wired from the surface (a branching dag); the module's single
    // public request port is bound to the first of them in sorted role order.
    let mut edges_chirho = Vec::new();
    let mut entry_role_chirho: Option<&RoleChirho> = None;
    for role_chirho in &dag_chirho.roles_chirho {
        for port_chirho in &role_chirho.in_ports_chirho {
            if let Some(PortSourceChirho::WireChirho { target_chirho }) = &port_chirho.source_chirho
            {
                if wire_from_surface_chirho(target_chirho) {
                    if matches!(
                        role_chirho.binding_chirho,
                        RoleBindingChirho::BuiltinPhiChirho(_)
                    ) {
                        return Err(format!(
                            "dag '{dag_name_chirho}' wires phi role '{}' from the surface; a phi merges branch outputs and cannot be an entry node",
                            role_chirho.name_chirho
                        ));
                    }
                    entry_role_chirho.get_or_insert(role_chirho);
                } else if let Some(producer_name_chirho) = wire_producer_role_chirho(target_chirho)
                {
                    let producer_chirho = dag_chirho
                        .roles_chirho
                        .iter()
                        .find(|candidate_chirho| candidate_chirho.name_chirho == producer_name_chirho)
                        .ok_or_else(|| {
                            format!(
                                "dag '{dag_name_chirho}' role '{}' is wired from '{producer_name_chirho}', which is not a role of this dag",
                                role_chirho.name_chirho
                            )
                        })?;
                    edges_chirho.push(EdgeChirho {
                        from_node_chirho: strip_chirho_suffix_chirho(&producer_name_chirho),
                        from_port_chirho: role_output_port_name_chirho(producer_chirho),
                        to_node_chirho: strip_chirho_suffix_chirho(&role_chirho.name_chirho),
                        to_port_chirho: role_input_port_name_chirho(role_chirho, port_chirho),
                        privacy_chirho: private_edge_for_port_chirho(port_chirho),
                    });
                }
            }
        }
    }
    let entry_role_chirho = entry_role_chirho.ok_or_else(|| {
        format!("dag '{dag_name_chirho}' has no role wired from the surface input (no entry node)")
    })?;
    let exit_role_name_chirho = surface_out_role_chirho(dag_chirho).ok_or_else(|| {
        format!("dag '{dag_name_chirho}' surface output does not link to a role output")
    })?;
    let exit_role_chirho = dag_chirho
        .roles_chirho
        .iter()
        .find(|candidate_chirho| candidate_chirho.name_chirho == exit_role_name_chirho)
        .ok_or_else(|| {
            format!(
                "dag '{dag_name_chirho}' surface output links to '{exit_role_name_chirho}', which is not a role of this dag"
            )
        })?;

    let base_chirho = strip_chirho_suffix_chirho(&dag_chirho.name_chirho);
    let dag_id_chirho = format!("{base_chirho}_dag");
    let module_id_chirho = format!("{base_chirho}_module");

    Ok(LoweredDagChirho {
        nodes_chirho,
        dag_chirho: DagOutChirho {
            id_chirho: dag_id_chirho.clone(),
            nodes_chirho: dag_chirho
                .roles_chirho
                .iter()
                .map(|r_chirho| strip_chirho_suffix_chirho(&r_chirho.name_chirho))
                .collect(),
            edges_chirho,
        },
        module_chirho: ModuleChirho {
            id_chirho: module_id_chirho.clone(),
            dag_chirho: dag_id_chirho,
            name_chirho: dag_chirho.name_chirho.clone(),
            version_chirho: "v1".to_string(),
            input_bindings_chirho: vec![BindingChirho {
                public_name_chirho: "request_chirho".to_string(),
                node_chirho: strip_chirho_suffix_chirho(&entry_role_chirho.name_chirho),
                node_port_chirho: "in".to_string(),
            }],
            output_bindings_chirho: vec![BindingChirho {
                public_name_chirho: "response_chirho".to_string(),
                node_chirho: strip_chirho_suffix_chirho(&exit_role_chirho.name_chirho),
                node_port_chirho: role_output_port_name_chirho(exit_role_chirho),
            }],
            route_labels_chirho,
        },
        module_id_chirho,
    })
}

/// Emit the app-source manifest from the dag tree + descriptor: the root dag plus any additional
/// route dags, each lowered to a node-set + dag + module, wired into one deploy (root + routes).
/// Part of `spec-chirho/workflows-chirho/tree-build-internal-module-emit-chirho.md`.
pub fn emit_manifest_chirho(
    tree_chirho: &AppTreeChirho,
    descriptor_chirho: &AppDescriptorChirho,
) -> Result<serde_json::Value, String> {
    if descriptor_chirho.root_chirho.key_access_chirho.is_some() {
        return Err(
            "the app root cannot be opened to limited keys; open a named route instead".to_string(),
        );
    }
    let root_chirho = lower_dag_chirho(
        tree_chirho,
        descriptor_chirho,
        &descriptor_chirho.root_chirho.dag_chirho,
        vec![descriptor_chirho.root_chirho.route_label_chirho.clone()],
    )?;

    let mut nodes_chirho = root_chirho.nodes_chirho;
    let mut dags_chirho = vec![root_chirho.dag_chirho];
    let mut modules_chirho = vec![root_chirho.module_chirho];
    let mut routes_chirho = Vec::new();

    let mut append_lowered_chirho = |lowered_chirho: LoweredDagChirho| {
        for node_chirho in lowered_chirho.nodes_chirho {
            if !nodes_chirho
                .iter()
                .any(|existing_chirho| existing_chirho.id_chirho == node_chirho.id_chirho)
            {
                nodes_chirho.push(node_chirho);
            }
        }
        dags_chirho.push(lowered_chirho.dag_chirho);
        modules_chirho.push(lowered_chirho.module_chirho);
    };

    for route_def_chirho in &descriptor_chirho.route_chirho {
        let lowered_chirho = lower_dag_chirho(
            tree_chirho,
            descriptor_chirho,
            &route_def_chirho.dag_chirho,
            vec![route_def_chirho.route_chirho.clone()],
        )?;
        let module_id_chirho = lowered_chirho.module_id_chirho.clone();
        append_lowered_chirho(lowered_chirho);
        routes_chirho.push(DeployRouteChirho {
            route_chirho: route_def_chirho.route_chirho.clone(),
            source_chirho: DeployRootChirho {
                kind_chirho: "module-id-chirho".to_string(),
                id_chirho: module_id_chirho,
            },
            input_mode_chirho: input_mode_chirho(
                &route_def_chirho.input_mode_chirho,
                route_def_chirho.subject_chirho.as_deref(),
                &route_def_chirho.safe_metadata_chirho,
            )?,
            request_body_policy_chirho: request_body_policy_chirho(
                route_def_chirho.request_body_policy_chirho.as_deref(),
            )?,
            key_access_chirho: key_access_chirho(route_def_chirho)?,
            response_content_type_chirho: Some(DEFAULT_RESPONSE_CONTENT_TYPE_CHIRHO.to_string()),
        });
    }

    for internal_module_chirho in &descriptor_chirho.internal_module_chirho {
        let lowered_chirho = lower_dag_chirho(
            tree_chirho,
            descriptor_chirho,
            &internal_module_chirho.dag_chirho,
            Vec::new(),
        )?;
        append_lowered_chirho(lowered_chirho);
    }

    let contract_refs_chirho = blessed_contract_refs_chirho(tree_chirho, &nodes_chirho);
    let manifest_chirho = ManifestChirho {
        schema_chirho: "app-source-manifest-v1-chirho".to_string(),
        app_chirho: descriptor_chirho.app_chirho.clone(),
        owner_chirho: descriptor_chirho.owner_chirho.clone(),
        nodes_chirho,
        dags_chirho,
        modules_chirho,
        assets_chirho: descriptor_chirho
            .asset_chirho
            .iter()
            .map(|asset_chirho| AssetChirho {
                name_chirho: asset_chirho.name_chirho.clone(),
                content_type_chirho: asset_chirho.content_type_chirho.clone(),
                source_chirho: AssetSourceChirho::PathChirho {
                    path_chirho: asset_chirho.path_chirho.clone(),
                },
            })
            .collect(),
        contract_refs_chirho,
        deploy_chirho: DeployChirho {
            root_chirho: DeployRootChirho {
                kind_chirho: "module-id-chirho".to_string(),
                id_chirho: root_chirho.module_id_chirho,
            },
            request_access_policy_chirho: request_access_policy_chirho(
                descriptor_chirho.request_access_policy_chirho.as_deref(),
            )?,
            input_mode_chirho: input_mode_chirho(
                &descriptor_chirho.root_chirho.input_mode_chirho,
                descriptor_chirho.root_chirho.subject_chirho.as_deref(),
                &descriptor_chirho.root_chirho.safe_metadata_chirho,
            )?,
            request_body_policy_chirho: request_body_policy_chirho(
                descriptor_chirho
                    .root_chirho
                    .request_body_policy_chirho
                    .as_deref(),
            )?,
            routes_chirho,
            target_chirho: TargetChirho {
                kind_chirho: "local-deploy-chirho".to_string(),
            },
            response_content_type_chirho: Some(DEFAULT_RESPONSE_CONTENT_TYPE_CHIRHO.to_string()),
        },
    };
    serde_json::to_value(&manifest_chirho).map_err(|e_chirho| e_chirho.to_string())
}

/// Single source of the exact stdout bytes the `tree-build-chirho emit <app_root>` CLI writes:
/// pretty-printed manifest JSON plus one terminal newline. The CLI and any in-process reviewer
/// (e.g. the credits-demo LocalPhaseB smoke) MUST both consume this one producer so the RAW
/// manifest hash they record reproduces byte-for-byte. Part of
/// `spec-chirho/workflows-chirho/tree-build-internal-module-emit-chirho.md`.
pub fn emit_manifest_bytes_chirho(
    tree_chirho: &AppTreeChirho,
    descriptor_chirho: &AppDescriptorChirho,
) -> Result<Vec<u8>, String> {
    let manifest_chirho = emit_manifest_chirho(tree_chirho, descriptor_chirho)?;
    let mut bytes_chirho = serde_json::to_string_pretty(&manifest_chirho)
        .map_err(|error_chirho| error_chirho.to_string())?
        .into_bytes();
    bytes_chirho.push(b'\n');
    Ok(bytes_chirho)
}

/// The (suffixed) name of the role whose output the dag surface links to.
fn surface_out_role_chirho(dag_chirho: &DagChirho) -> Option<String> {
    let out_port_chirho = dag_chirho
        .surface_chirho
        .out_ports_chirho
        .iter()
        .find(|p_chirho| p_chirho.parsed_chirho.direction_chirho == DirectionChirho::OutChirho)?;
    let link_chirho = dag_chirho
        .dir_chirho
        .join("surface_chirho")
        .join(&out_port_chirho.raw_name_chirho);
    let target_chirho = std::fs::read_link(&link_chirho).ok()?;
    wire_producer_role_chirho(&target_chirho)
}

/// Load the app descriptor from `<app_root>/app-chirho.toml`.
pub fn load_app_descriptor_chirho(app_root_chirho: &Path) -> Result<AppDescriptorChirho, String> {
    let path_chirho = app_root_chirho.join("app-chirho.toml");
    let text_chirho = std::fs::read_to_string(&path_chirho)
        .map_err(|e_chirho| format!("read app-chirho.toml: {e_chirho}"))?;
    toml::from_str(&text_chirho).map_err(|e_chirho| format!("parse app-chirho.toml: {e_chirho}"))
}

#[cfg(test)]
#[path = "emit_tests_chirho.rs"]
mod tests_chirho;
