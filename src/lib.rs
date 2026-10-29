// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! cairn-chirho — a content-addressed, capability-secured, versioned dataflow DAG runtime.
//!
//! Caching, versioning, and audit are three views of one Merkle DAG; rollback is moving a ref.
//! Library root.

// Our identifiers carry the `Chirho` suffix by convention, so every enum's variants share it.
#![allow(clippy::enum_variant_names)]

#[cfg(all(test, feature = "prototype-full-chirho"))]
#[path = "execution_runtime_chirho/provider_test_support_chirho.rs"]
pub(crate) mod provider_test_support_chirho;

// The lean foundation (hashes, model types, typed object store, refs) lives in the dep-light
// `cairn-core-chirho` workspace crate. The full prototype depends on it and re-exports it here, so
// `crate::model_chirho` / `cas_chirho` / `store_chirho` / `refs_chirho` resolve to the one
// canonical definition — not a second copy compiled separately into this crate.
pub use cairn_core_chirho::{
    cas_chirho, dag_capability_scan_chirho, model_chirho, object_graph_chirho, refs_chirho,
    store_chirho,
};
pub use cairn_model_agent_authority_chirho as agent_authority_model_chirho;
pub use cairn_model_agent_report_chirho as agent_report_model_chirho;
pub use cairn_model_app_chirho as app_model_chirho;
pub use cairn_model_economic_chirho as economic_model_chirho;
pub use cairn_model_gate1_chirho as gate1_model_chirho;
pub use cairn_model_identity_chirho as identity_model_chirho;
pub use cairn_model_privacy_chirho as privacy_model_chirho;
pub use cairn_model_review_chirho as review_model_chirho;
pub use cairn_model_runtime_chirho as runtime_model_chirho;

#[cfg(feature = "prototype-full-chirho")]
#[path = "governance_flows_chirho/elected_control_prepare_chirho.rs"]
mod elected_control_prepare_chirho;

#[cfg(feature = "prototype-full-chirho")]
#[path = "governance_flows_chirho/agent_authority_chirho/mod.rs"]
pub mod agent_authority_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "governance_flows_chirho/agent_report_chirho.rs"]
pub mod agent_report_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "app_authoring_chirho/app_build_request_chirho.rs"]
pub mod app_build_request_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "app_runtime_chirho/app_chirho.rs"]
pub mod app_chirho;
#[path = "app_authoring_chirho/app_descriptor_chirho.rs"]
pub mod app_descriptor_chirho;
// The pure descriptor->Markdown/MCP renderers moved to cairn-app-docs-chirho; re-exported here so
// `cairn_chirho::app_docs_chirho::*` paths stay identical for the CLI and serve-runtime consumers.
pub use cairn_app_docs_chirho::app_docs_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "app_authoring_chirho/app_manifest_chirho.rs"]
pub mod app_manifest_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "app_runtime_chirho/app_source_manifest_chirho.rs"]
pub mod app_source_manifest_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "app_authoring_chirho/attenuation_chirho.rs"]
pub mod attenuation_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "governance_flows_chirho/audit_chirho.rs"]
pub mod audit_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "app_authoring_chirho/blessed_chirho.rs"]
pub mod blessed_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "execution_runtime_chirho/cache_chirho.rs"]
pub mod cache_chirho;
#[path = "app_runtime_chirho/publication_chirho.rs"]
pub mod publication_chirho;
#[cfg(feature = "prototype-full-chirho")]
pub use cairn_capability_chirho::{
    capability_key_grant_chirho, capability_plain_chirho, capability_spec_chirho,
};
#[cfg(feature = "prototype-full-chirho")]
pub use cairn_compile_chirho::compile_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "privacy_compliance_chirho/compliance_evidence_chirho.rs"]
pub mod compliance_evidence_chirho;
#[cfg(feature = "prototype-full-chirho")]
pub use cairn_config_chirho::config_chirho;
#[cfg(feature = "prototype-full-chirho")]
pub use cairn_dag_author_chirho::dag_author_chirho;
#[cfg(feature = "prototype-full-chirho")]
pub use cairn_durable_chirho as durable_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "execution_runtime_chirho/dag_chirho.rs"]
pub mod dag_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "app_authoring_chirho/dag_module_chirho.rs"]
pub mod dag_module_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "app_authoring_chirho/dag_private_value_chirho.rs"]
pub mod dag_private_value_chirho;
// RD5/W4 brick 2: moved to `cairn-compliance-reporting-chirho`. Re-exported at the same root path so
// external consumers (`cairn-cli-chirho`, `cairn-report-command-chirho`, `cairn-operator-smoke-chirho`)
// reach it as `cairn_chirho::data_residency_chirho` with zero edits.
#[cfg(feature = "prototype-full-chirho")]
pub use cairn_compliance_reporting_chirho::data_residency_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "privacy_compliance_chirho/data_rights_chirho.rs"]
pub mod data_rights_chirho;
#[cfg(feature = "prototype-full-chirho")]
pub use cairn_display_chirho as display_chirho;
#[path = "edge_flows_chirho/dns_apply_chirho.rs"]
pub mod dns_apply_chirho;
#[path = "edge_flows_chirho/dns_zone_chirho.rs"]
pub mod dns_zone_chirho;
#[path = "edge_flows_chirho/domain_binding_chirho.rs"]
pub mod domain_binding_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "execution_runtime_chirho/effect_chirho.rs"]
pub mod effect_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "execution_runtime_chirho/gate1_anchor_chirho.rs"]
pub mod gate1_anchor_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "governance_flows_chirho/gc_chirho.rs"]
pub mod gc_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "governance_flows_chirho/graph_chirho.rs"]
pub mod graph_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "distributed_replication_chirho/source_export_chirho.rs"]
pub mod replication_source_export_chirho;
#[cfg(feature = "prototype-full-chirho")]
pub use cairn_head_removal_chirho::head_removal_chirho;
pub use cairn_head_removal_chirho::head_removal_transition_chirho;
#[path = "operator_flows_chirho/hosting_status_chirho.rs"]
pub mod hosting_status_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "edge_flows_chirho/identity_chirho.rs"]
pub mod identity_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "execution_runtime_chirho/index_chirho.rs"]
pub mod index_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "governance_flows_chirho/legal_hold_chirho.rs"]
pub mod legal_hold_chirho;
// The CF6-D2 brick (a) acceptance instrument: pins the bytes the legacy credit-hold, billing
// compensation and billing usage evidence readers emit, so the extraction cannot silently change
// what a subject export contains.
//
// NESTED rather than declared with `#[cfg(all(test, feature = ...))]`, and the nesting is load
// bearing. The source scanner treats a module as test-only via `has_exact_cfg_test_attribute_chirho`,
// which matches the BARE `#[cfg(test)]` — a compound `cfg(all(test, ...))` stringifies differently
// and is deliberately treated as ambiguous, and ambiguity FAILS SAFE by keeping the file in the
// production surface. That is right for a guard, but it meant this test file was counted as
// production: it inflated the root crate's line total past its recorded loan and added four
// cross-family import edges to the root ratchet. Putting the feature gate on an outer module lets
// the inner declaration be the bare form the scanner recognises.
// ATTEMPTED AND REVERTED (2026-07-25): nesting the bare `#[cfg(test)]` inside a feature-gated outer
// module, so the scanner's `has_exact_cfg_test_attribute_chirho` would recognise it and stop counting
// this test file as production. It does not work here — `#[path]` inside an INLINE module resolves
// against `src/<outer module>/`, and that directory does not exist, so neither the direct nor the
// `../` form resolves. Making it work would mean moving the file into a directory named for the
// outer module, which is churn for a metrics artefact.
//
// So the compound cfg stays, and the consequence is recorded rather than hidden: the scanner treats
// `cfg(all(test, ...))` as ambiguous and FAILS SAFE by keeping the file in the production surface.
// That is correct for a guard. It means these ~470 test lines and their four cross-family imports
// count as production until brick (a) moves them, which is what the open loans below cover.
// CF6-D2 brick (a1): the read-only legacy evidence readers, extracted so they survive the spine's
// deletion. Clean half only -- every load_* reader is free of old-road machinery; verify_* is (a2).
#[cfg(all(test, feature = "prototype-full-chirho"))]
#[path = "privacy_compliance_chirho/legacy_evidence_characterization_tests_chirho.rs"]
mod legacy_evidence_characterization_tests_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "privacy_compliance_chirho/legacy_evidence_readers_chirho.rs"]
pub mod legacy_evidence_readers_chirho;
// CF6-D2: the single-road gate all three retained evidence modules need. Its own module because
// none of them reaches it THROUGH another, and because a fail-closed gate is not a reader.
// `pub(crate) mod` rather than bare `mod` deliberately: at the crate root the two have identical
// reach, but if these `#[path]` mounts are ever grouped under a parent module the bare form
// SILENTLY narrows to that subtree while this one keeps its promise. Not `pub mod` -- this is
// genuinely not crate-public.
#[cfg(feature = "prototype-full-chirho")]
#[path = "legacy_evidence_chirho/legacy_single_road_probe_chirho.rs"]
pub(crate) mod legacy_single_road_probe_chirho;
// CF6-D2 brick (a2-0): the money-integrity pins for the shared ledger read/verify core. They live
// OUTSIDE src/economic_flows_chirho on purpose -- the ledger's own test module is inside the delete
// scope, so its money pins protect the move and then die with the spine.
#[cfg(all(test, feature = "prototype-full-chirho"))]
#[path = "legacy_evidence_chirho/legacy_ledger_characterization_tests_chirho.rs"]
mod legacy_ledger_characterization_tests_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "legacy_evidence_chirho/legacy_ledger_evidence_chirho.rs"]
pub mod legacy_ledger_evidence_chirho;
// CF6-D2 brick (a2-2): the money-integrity pins for the credit-hold read/verify core, landed before
// the move for the same reason (a2-0)'s were -- the holds module's own tests are inside the delete
// scope, so they protect the move and then die with the spine.
#[cfg(all(test, feature = "prototype-full-chirho"))]
#[path = "legacy_evidence_chirho/legacy_holds_characterization_tests_chirho.rs"]
mod legacy_holds_characterization_tests_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "legacy_evidence_chirho/legacy_holds_evidence_chirho.rs"]
pub mod legacy_holds_evidence_chirho;
// CF6-D2 brick (a2-3): the money-integrity pins for the billing usage read/verify core, and the
// retained module they guard. Same reason again -- billing's own tests are inside the delete scope,
// so these protect the move and then die with the spine.
#[cfg(all(test, feature = "prototype-full-chirho"))]
#[path = "legacy_evidence_chirho/legacy_billing_characterization_tests_chirho.rs"]
mod legacy_billing_characterization_tests_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "legacy_evidence_chirho/legacy_billing_evidence_chirho.rs"]
pub mod legacy_billing_evidence_chirho;
#[path = "edge_flows_chirho/mailbox_apply_chirho.rs"]
pub mod mailbox_apply_chirho;
#[path = "edge_flows_chirho/mailbox_chirho.rs"]
pub mod mailbox_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "execution_runtime_chirho/native_worker_chirho.rs"]
pub mod native_worker_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "edge_flows_chirho/oauth_chirho.rs"]
pub mod oauth_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "edge_flows_chirho/onboarding_chirho.rs"]
pub mod onboarding_chirho;
#[cfg(feature = "prototype-full-chirho")]
pub use cairn_operator_evidence_chirho::operator_evidence_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "operator_flows_chirho/ops_custody_chirho.rs"]
pub mod ops_custody_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "operator_flows_chirho/ops_restore_drill_chirho.rs"]
pub mod ops_restore_drill_chirho;
#[cfg(feature = "prototype-full-chirho")]
pub use cairn_perffection_platform_chirho::platform_mcp_chirho;
#[cfg(feature = "prototype-full-chirho")]
pub use cairn_placement_chirho as placement_chirho;
#[path = "app_runtime_chirho/effect_pricing_chirho.rs"]
pub mod effect_pricing_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "governance_flows_chirho/privacy_backup_chirho.rs"]
pub mod privacy_backup_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "privacy_compliance_chirho/privacy_chirho.rs"]
pub mod privacy_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "app_runtime_chirho/publish_chirho.rs"]
pub mod publish_chirho;
#[cfg(feature = "prototype-full-chirho")]
pub use cairn_query_chirho::query_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "privacy_compliance_chirho/realtime_ledger_bound_evidence_chirho.rs"]
pub mod realtime_ledger_bound_evidence_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "privacy_compliance_chirho/realtime_legacy_evidence_chirho.rs"]
pub mod realtime_legacy_evidence_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "app_metering_chirho/resource_chirho.rs"]
pub mod resource_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "privacy_compliance_chirho/retention_chirho.rs"]
pub mod retention_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "privacy_compliance_chirho/reversion_legacy_evidence_chirho.rs"]
pub mod reversion_legacy_evidence_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "governance_flows_chirho/review_chirho/mod.rs"]
pub mod review_chirho;
#[cfg(feature = "prototype-full-chirho")]
pub use cairn_wasmtime_runner_chirho::runner_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "operator_flows_chirho/runtime_profile_chirho.rs"]
pub mod runtime_profile_chirho;
#[cfg(feature = "prototype-full-chirho")]
pub use cairn_secret_chirho::secret_chirho;
#[cfg(feature = "prototype-full-chirho")]
pub use cairn_seqlog_chirho::seqlog_chirho;
#[cfg(feature = "prototype-full-chirho")]
pub use cairn_source_scan_chirho::source_scan_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "privacy_compliance_chirho/store_seal_chirho.rs"]
pub mod store_seal_chirho;
#[cfg(feature = "prototype-full-chirho")]
pub use cairn_tenant_chirho::migration_completeness_chirho;
#[cfg(feature = "prototype-full-chirho")]
pub use cairn_tenant_chirho::root_surfaces_chirho;
#[cfg(feature = "prototype-full-chirho")]
pub use cairn_tenant_chirho::self_containment_chirho;
#[cfg(feature = "prototype-full-chirho")]
pub use cairn_tenant_chirho::single_customer_app_chirho;
#[cfg(feature = "prototype-full-chirho")]
pub use cairn_tenant_chirho::surface_disposition_chirho;
#[cfg(feature = "prototype-full-chirho")]
pub use cairn_tenant_chirho::tenant_chirho;
#[cfg(feature = "prototype-full-chirho")]
#[path = "governance_flows_chirho/verify_chirho.rs"]
pub mod verify_chirho;
#[cfg(feature = "prototype-full-chirho")]
pub use cairn_store_redb_chirho::versioned_chirho;
#[cfg(feature = "prototype-full-chirho")]
pub use cairn_writer_head_chirho::writer_head_chirho;
