// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Generated app docs: turn a per-app API descriptor into human-readable Markdown and an MCP tool manifest, so the same source of truth produces both the page an owner reads and the tools an agent calls.

use crate::app_descriptor_chirho::AppDescriptorChirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One MCP tool derived from an app route: the agent calls it by POSTing to `path`, and the
/// description is the route's honest plain-language capability verdict.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpToolChirho {
    pub name_chirho: String,
    pub description_chirho: String,
    pub method_chirho: String,
    pub path_chirho: String,
    pub input_mode_chirho: String,
    pub input_schema_chirho: serde_json::Value,
}

/// An app's whole MCP tool manifest — what an agent loads to drive the app.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpManifestChirho {
    pub schema_chirho: String,
    pub app_chirho: String,
    pub tools_chirho: Vec<McpToolChirho>,
}

/// Make a stable, identifier-safe MCP tool name from an app and optional route.
fn tool_name_chirho(app_chirho: &str, route_chirho: Option<&str>) -> String {
    let sanitize_chirho = |s_chirho: &str| -> String {
        s_chirho
            .chars()
            .map(|c_chirho| {
                if c_chirho.is_ascii_alphanumeric() {
                    c_chirho
                } else {
                    '_'
                }
            })
            .collect::<String>()
    };
    match route_chirho {
        Some(route_chirho) => format!(
            "{}__{}",
            sanitize_chirho(app_chirho),
            sanitize_chirho(route_chirho)
        ),
        None => sanitize_chirho(app_chirho),
    }
}

fn tool_name_suffix_chirho(app_chirho: &str, route_chirho: Option<&str>) -> String {
    let raw_chirho = format!(
        "{app_chirho}\0{}",
        route_chirho.unwrap_or("(default-route-chirho)")
    );
    let hex_chirho = blake3::hash(raw_chirho.as_bytes()).to_hex().to_string();
    hex_chirho[..8].to_string()
}

/// Build the MCP tool manifest for an app from its descriptor (pure transform).
pub fn app_mcp_manifest_chirho(descriptor_chirho: &AppDescriptorChirho) -> McpManifestChirho {
    let mut tool_name_counts_chirho = BTreeMap::new();
    for route_chirho in &descriptor_chirho.routes_chirho {
        let base_name_chirho = tool_name_chirho(
            &descriptor_chirho.app_chirho,
            route_chirho.route_chirho.as_deref(),
        );
        *tool_name_counts_chirho
            .entry(base_name_chirho)
            .or_insert(0_usize) += 1;
    }
    let tools_chirho = descriptor_chirho
        .routes_chirho
        .iter()
        .map(|route_chirho| {
            let base_name_chirho = tool_name_chirho(
                &descriptor_chirho.app_chirho,
                route_chirho.route_chirho.as_deref(),
            );
            let name_chirho = if tool_name_counts_chirho
                .get(&base_name_chirho)
                .copied()
                .unwrap_or(0)
                > 1
            {
                format!(
                    "{}__{}",
                    base_name_chirho,
                    tool_name_suffix_chirho(
                        &descriptor_chirho.app_chirho,
                        route_chirho.route_chirho.as_deref()
                    )
                )
            } else {
                base_name_chirho
            };
            // Plain bodies accept any JSON/text; private-encrypted bodies are sealed before the DAG
            // sees them, so an agent still just sends the data — the platform encrypts it.
            let input_schema_chirho = serde_json::json!({
                "type": "object",
                "description": format!(
                    "Request body for {} (input mode: {}).",
                    route_chirho.path_chirho, route_chirho.input_mode_chirho
                ),
            });
            McpToolChirho {
                name_chirho,
                description_chirho: route_chirho
                    .capability_summary_chirho
                    .sentence_chirho
                    .clone(),
                method_chirho: "POST".to_string(),
                path_chirho: route_chirho.path_chirho.clone(),
                input_mode_chirho: route_chirho.input_mode_chirho.clone(),
                input_schema_chirho,
            }
        })
        .collect();
    McpManifestChirho {
        schema_chirho: "app-mcp-manifest-v1-chirho".to_string(),
        app_chirho: descriptor_chirho.app_chirho.clone(),
        tools_chirho,
    }
}

/// Render a human-readable Markdown API reference for an app from its descriptor (pure transform).
pub fn app_docs_markdown_chirho(descriptor_chirho: &AppDescriptorChirho) -> String {
    let mut out_chirho = String::new();
    out_chirho.push_str(&format!(
        "# {} — API reference\n\n",
        descriptor_chirho.app_chirho
    ));
    out_chirho.push_str(&format!(
        "Status: {}. {} route(s).\n\n",
        if descriptor_chirho.active_chirho {
            "deployed"
        } else {
            "not deployed"
        },
        descriptor_chirho.route_count_chirho
    ));
    out_chirho.push_str(
        "Generated from the app's content-addressed definitions. Each route lists exactly what it can do.\n\n",
    );
    for route_chirho in &descriptor_chirho.routes_chirho {
        let title_chirho = route_chirho
            .route_chirho
            .as_deref()
            .unwrap_or("(default surface)");
        out_chirho.push_str(&format!("## {title_chirho}\n\n"));
        out_chirho.push_str(&format!("- Path: `{}`\n", route_chirho.path_chirho));
        out_chirho.push_str("- Method: `GET` (no body) or `POST` (with a request body)\n");
        out_chirho.push_str(&format!(
            "- Request body handling: {}\n",
            route_chirho.input_mode_chirho
        ));
        if let Some(content_type_chirho) = &route_chirho.response_content_type_chirho {
            out_chirho.push_str(&format!("- Responds with: `{content_type_chirho}`\n"));
        }
        out_chirho.push_str(&format!(
            "- What it can do: {}\n\n",
            route_chirho.capability_summary_chirho.sentence_chirho
        ));
    }
    out_chirho
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::app_descriptor_chirho::{AppDescriptorChirho, AppRouteDescriptorChirho};
    use cairn_capability_chirho::capability_plain_chirho;
    use cairn_core_chirho::model_chirho::CapabilityChirho;

    fn descriptor_chirho() -> AppDescriptorChirho {
        let write_summary_chirho = capability_plain_chirho::summarize_capabilities_chirho(&[
            CapabilityChirho::WriteStoreChirho {
                prefix_chirho: "contact/".to_string(),
            },
        ]);
        let pure_summary_chirho = capability_plain_chirho::summarize_capabilities_chirho(&[]);
        AppDescriptorChirho {
            schema_chirho: "app-descriptor-v1-chirho".to_string(),
            app_chirho: "card-shop".to_string(),
            active_chirho: true,
            route_count_chirho: 2,
            routes_chirho: vec![
                AppRouteDescriptorChirho {
                    path_chirho: "/app-chirho/card-shop".to_string(),
                    route_chirho: None,
                    input_mode_chirho: "plain".to_string(),
                    response_content_type_chirho: Some("text/html".to_string()),
                    capability_summary_chirho: pure_summary_chirho,
                },
                AppRouteDescriptorChirho {
                    path_chirho: "/app-chirho/card-shop/orders".to_string(),
                    route_chirho: Some("orders".to_string()),
                    input_mode_chirho: "private-encrypted".to_string(),
                    response_content_type_chirho: None,
                    capability_summary_chirho: write_summary_chirho,
                },
            ],
        }
    }

    #[test]
    fn mcp_manifest_maps_routes_to_tools_chirho() {
        let manifest_chirho = app_mcp_manifest_chirho(&descriptor_chirho());
        assert_eq!(manifest_chirho.schema_chirho, "app-mcp-manifest-v1-chirho");
        assert_eq!(manifest_chirho.tools_chirho.len(), 2);
        // Tool names are identifier-safe (the dash in "card-shop" becomes "_").
        assert_eq!(manifest_chirho.tools_chirho[0].name_chirho, "card_shop");
        assert_eq!(
            manifest_chirho.tools_chirho[1].name_chirho,
            "card_shop__orders"
        );
        // The tool description is the honest capability verdict.
        assert!(manifest_chirho.tools_chirho[0]
            .description_chirho
            .contains("cannot touch the outside world"));
        assert!(manifest_chirho.tools_chirho[1]
            .description_chirho
            .contains("save data under \"contact/\""));
        assert_eq!(
            manifest_chirho.tools_chirho[1].input_mode_chirho,
            "private-encrypted"
        );
        // The manifest serializes to JSON cleanly (an agent loads this).
        let json_chirho = serde_json::to_string(&manifest_chirho).unwrap();
        assert!(json_chirho.contains("app-mcp-manifest-v1-chirho"));
    }

    #[test]
    fn markdown_lists_routes_with_verdicts_chirho() {
        let markdown_chirho = app_docs_markdown_chirho(&descriptor_chirho());
        assert!(markdown_chirho.starts_with("# card-shop — API reference"));
        assert!(markdown_chirho.contains("/app-chirho/card-shop/orders"));
        assert!(markdown_chirho.contains("private-encrypted"));
        assert!(markdown_chirho.contains("text/html"));
        assert!(markdown_chirho.contains("save data under \"contact/\""));
        assert!(markdown_chirho.contains("cannot touch the outside world"));
    }

    #[test]
    fn tool_name_sanitizes_non_identifier_chars_chirho() {
        assert_eq!(tool_name_chirho("my.app", Some("a-b")), "my_app__a_b");
        assert_eq!(tool_name_chirho("plain", None), "plain");
    }

    #[test]
    fn mcp_manifest_disambiguates_sanitized_tool_name_collisions_chirho() {
        let summary_chirho = capability_plain_chirho::summarize_capabilities_chirho(&[]);
        let descriptor_chirho = AppDescriptorChirho {
            schema_chirho: "app-descriptor-v1-chirho".to_string(),
            app_chirho: "card-shop".to_string(),
            active_chirho: true,
            route_count_chirho: 2,
            routes_chirho: vec![
                AppRouteDescriptorChirho {
                    path_chirho: "/app-chirho/card-shop/a-b".to_string(),
                    route_chirho: Some("a-b".to_string()),
                    input_mode_chirho: "plain".to_string(),
                    response_content_type_chirho: None,
                    capability_summary_chirho: summary_chirho.clone(),
                },
                AppRouteDescriptorChirho {
                    path_chirho: "/app-chirho/card-shop/a_b".to_string(),
                    route_chirho: Some("a_b".to_string()),
                    input_mode_chirho: "plain".to_string(),
                    response_content_type_chirho: None,
                    capability_summary_chirho: summary_chirho,
                },
            ],
        };
        let manifest_chirho = app_mcp_manifest_chirho(&descriptor_chirho);
        assert_eq!(manifest_chirho.tools_chirho.len(), 2);
        assert_ne!(
            manifest_chirho.tools_chirho[0].name_chirho,
            manifest_chirho.tools_chirho[1].name_chirho
        );
        assert!(manifest_chirho.tools_chirho[0]
            .name_chirho
            .starts_with("card_shop__a_b__"));
        assert!(manifest_chirho.tools_chirho[1]
            .name_chirho
            .starts_with("card_shop__a_b__"));
    }
}
