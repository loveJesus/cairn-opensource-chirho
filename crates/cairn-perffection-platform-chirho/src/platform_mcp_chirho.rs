// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Platform MCP catalog: the owner-facing platform tools an agent can drive, each marked read-only or gated-action — one control plane, two skins (CLI/UI and MCP), with no MCP-only mutations.
//!
//! This describes tools that ALREADY exist as cairn commands; it never introduces a new mutation
//! path. Gated actions are listed so an agent knows they exist, but carry `requires_owner_auth`
//! and `gated` so an agent (and a human) sees they need owner authorization, not a free call.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlatformToolKindChirho {
    /// Safe to call freely; returns information, changes nothing.
    ReadChirho,
    /// Changes platform/app state; requires owner authorization and (where relevant) review.
    GatedActionChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformMcpToolChirho {
    pub name_chirho: String,
    pub description_chirho: String,
    pub kind_chirho: PlatformToolKindChirho,
    /// The existing cairn command this tool maps to (the same surface a human uses).
    pub command_chirho: String,
    pub requires_owner_auth_chirho: bool,
    pub gated_chirho: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformMcpManifestChirho {
    pub schema_chirho: String,
    pub tool_count_chirho: usize,
    pub read_tool_count_chirho: usize,
    pub gated_action_count_chirho: usize,
    pub tools_chirho: Vec<PlatformMcpToolChirho>,
    pub nonclaim_chirho: String,
}

fn read_tool_chirho(
    name_chirho: &str,
    command_chirho: &str,
    description_chirho: &str,
) -> PlatformMcpToolChirho {
    PlatformMcpToolChirho {
        name_chirho: name_chirho.to_string(),
        description_chirho: description_chirho.to_string(),
        kind_chirho: PlatformToolKindChirho::ReadChirho,
        command_chirho: command_chirho.to_string(),
        requires_owner_auth_chirho: false,
        gated_chirho: false,
    }
}

fn gated_tool_chirho(
    name_chirho: &str,
    command_chirho: &str,
    description_chirho: &str,
) -> PlatformMcpToolChirho {
    PlatformMcpToolChirho {
        name_chirho: name_chirho.to_string(),
        description_chirho: description_chirho.to_string(),
        kind_chirho: PlatformToolKindChirho::GatedActionChirho,
        command_chirho: command_chirho.to_string(),
        requires_owner_auth_chirho: true,
        gated_chirho: true,
    }
}

/// Build the platform MCP tool catalog. Every entry maps to an existing cairn command — the same
/// surface a human uses — so an MCP skin never gains authority the CLI/UI doesn't already have.
pub fn platform_mcp_manifest_chirho() -> PlatformMcpManifestChirho {
    let tools_chirho = vec![
        read_tool_chirho(
            "app_capabilities",
            "app-capabilities --app <app> [--json]",
            "Show in plain language what a deployed app can do to the world (its capability verdict).",
        ),
        read_tool_chirho(
            "app_descriptor",
            "app-descriptor --app <app> [--json]",
            "Get a deployed app's agent-readable API descriptor: routes, input modes, and per-route capability verdicts.",
        ),
        read_tool_chirho(
            "app_docs",
            "app-docs --app <app> [--mcp]",
            "Generate a deployed app's API docs (Markdown) or its MCP tool manifest.",
        ),
        read_tool_chirho(
            "domain_bindings",
            "domain-bindings [--json]",
            "List the signed host/path-to-app domain bindings (fail-closed verified).",
        ),
        read_tool_chirho(
            "app_source_review",
            "app-source-review --manifest <path> [--owner <p>] [--json]",
            "Build a non-authoritative candidate review for a source manifest and show its declared capabilities, cost, and plain-language verdict before any promote.",
        ),
        read_tool_chirho(
            "domain_status",
            "domain-status --domain <d> [--json]",
            "Show a domain's hosting status: its live routing bindings and desired DNS zone in one view.",
        ),
        read_tool_chirho(
            "dns_zones",
            "dns-zones [--json]",
            "List the signed desired-state DNS zones (fail-closed verified).",
        ),
        read_tool_chirho(
            "mailboxes",
            "mailboxes --owner <p> [--json]",
            "List an owner's mailboxes/aliases as safe rows (no address plaintext — a hash and metadata only).",
        ),
        gated_tool_chirho(
            "dns_zone_set",
            "dns-zone-set --owner <p> --domain <d> --record \"TYPE,NAME,VALUE[,TTL[,PRIORITY]]\"...",
            "Set a domain's desired DNS zone (signed, rollbackable). Owner-authorized; live provider apply is a separate gated step.",
        ),
        gated_tool_chirho(
            "dns_apply_stub",
            "dns-apply-stub --owner <p> --domain <d> --idempotency-key <k>",
            "Record an intent to apply a domain's desired DNS zone via the no-network stub performer (idempotent). Live provider apply is operator-gated.",
        ),
        gated_tool_chirho(
            "mailbox_set",
            "mailbox-set --owner <p> --domain <d> --local-part <l> [--kind mailbox|alias] [--target <t>]",
            "Add a customer mailbox/alias (the address is sealed in a private blob). Owner-authorized; live Mailu provisioning is a separate gated step.",
        ),
        gated_tool_chirho(
            "mailbox_apply_stub",
            "mailbox-apply-stub --owner <p> --domain <d> --idempotency-key <k>",
            "Record an intent to provision a domain's live mailboxes via the no-network stub performer (idempotent). Live Mailu provisioning is operator-gated.",
        ),
        gated_tool_chirho(
            "domain_bind",
            "domain-bind --owner <p> --host <h> [--path </prefix>] --app <a> [--route <r>]",
            "Bind a host/path to an app. Owner-authorized signed write; the binding is rollbackable.",
        ),
        gated_tool_chirho(
            "domain_unbind",
            "domain-unbind --owner <p> --host <h> [--path </prefix>] --app <a>",
            "Remove a host/path-to-app binding (signed append-only removal).",
        ),
        gated_tool_chirho(
            "review_promote",
            "review-promote --app <a> --owner <p> --candidate <hash> ...",
            "Promote a reviewed candidate to live. Requires owner authorization after a human-reviewed capability verdict.",
        ),
        gated_tool_chirho(
            "rollback",
            "rollback <branch> <to>",
            "Roll an app/ref back to an earlier content hash (move the ref). Owner-authorized.",
        ),
    ];
    let read_tool_count_chirho = tools_chirho
        .iter()
        .filter(|t_chirho| t_chirho.kind_chirho == PlatformToolKindChirho::ReadChirho)
        .count();
    let gated_action_count_chirho = tools_chirho
        .iter()
        .filter(|t_chirho| t_chirho.kind_chirho == PlatformToolKindChirho::GatedActionChirho)
        .count();
    PlatformMcpManifestChirho {
        schema_chirho: "platform-mcp-manifest-v1-chirho".to_string(),
        tool_count_chirho: tools_chirho.len(),
        read_tool_count_chirho,
        gated_action_count_chirho,
        tools_chirho,
        nonclaim_chirho: "Every tool maps to an existing cairn command; the MCP skin adds no authority the CLI/UI lacks. Gated actions require owner authorization and (where relevant) review-before-promote; this manifest is a tool catalog, not a running MCP transport.".to_string(),
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn manifest_is_well_formed_and_counts_match_chirho() {
        let manifest_chirho = platform_mcp_manifest_chirho();
        assert_eq!(
            manifest_chirho.schema_chirho,
            "platform-mcp-manifest-v1-chirho"
        );
        assert_eq!(
            manifest_chirho.tool_count_chirho,
            manifest_chirho.tools_chirho.len()
        );
        assert_eq!(
            manifest_chirho.read_tool_count_chirho + manifest_chirho.gated_action_count_chirho,
            manifest_chirho.tool_count_chirho
        );
        assert!(manifest_chirho.read_tool_count_chirho >= 1);
        assert!(manifest_chirho.gated_action_count_chirho >= 1);
        // The H5 hosting tools must be discoverable through the platform catalog, with the
        // mutating ones gated.
        let by_name_chirho = |name_chirho: &str| {
            manifest_chirho
                .tools_chirho
                .iter()
                .find(|t_chirho| t_chirho.name_chirho == name_chirho)
                .unwrap_or_else(|| panic!("missing platform tool {name_chirho}"))
                .clone()
        };
        assert!(!by_name_chirho("domain_status").gated_chirho);
        assert!(!by_name_chirho("dns_zones").gated_chirho);
        assert!(!by_name_chirho("mailboxes").gated_chirho);
        assert!(by_name_chirho("dns_zone_set").gated_chirho);
        assert!(by_name_chirho("dns_apply_stub").gated_chirho);
        assert!(by_name_chirho("mailbox_set").gated_chirho);
        assert!(by_name_chirho("mailbox_apply_stub").gated_chirho);
    }

    #[test]
    fn gated_tools_require_owner_auth_read_tools_do_not_chirho() {
        for tool_chirho in platform_mcp_manifest_chirho().tools_chirho {
            match tool_chirho.kind_chirho {
                PlatformToolKindChirho::ReadChirho => {
                    assert!(
                        !tool_chirho.requires_owner_auth_chirho,
                        "read tool {} should not require auth",
                        tool_chirho.name_chirho
                    );
                    assert!(!tool_chirho.gated_chirho);
                }
                PlatformToolKindChirho::GatedActionChirho => {
                    assert!(
                        tool_chirho.requires_owner_auth_chirho,
                        "gated tool {} must require owner auth",
                        tool_chirho.name_chirho
                    );
                    assert!(tool_chirho.gated_chirho);
                }
            }
            assert!(!tool_chirho.command_chirho.is_empty());
            assert!(!tool_chirho.description_chirho.is_empty());
        }
    }

    #[test]
    fn manifest_serializes_for_an_agent_chirho() {
        let json_chirho = serde_json::to_string(&platform_mcp_manifest_chirho()).unwrap();
        assert!(json_chirho.contains("platform-mcp-manifest-v1-chirho"));
        assert!(json_chirho.contains("app_descriptor"));
        // The honesty nonclaim travels with the manifest.
        assert!(json_chirho.contains("adds no authority"));
    }
}
