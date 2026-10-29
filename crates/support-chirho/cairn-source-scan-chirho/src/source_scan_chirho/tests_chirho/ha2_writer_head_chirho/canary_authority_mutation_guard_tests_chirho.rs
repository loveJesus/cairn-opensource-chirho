// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! A canary may RECORD what it saw; it may never MUTATE the authority it is watching.
//!
//! WHY THIS EXISTS AS A WIRED GUARD. The Gate-1 suite already contains a canary writer-token
//! detector, but it is only ever handed an `r#"…"#` fixture — it proves it CAN spot a forbidden
//! write and is never pointed at the codebase. Pointing it at the real canaries as written would
//! FALSE-POSITIVE: `shadow_canary_chirho.rs` legitimately calls `write_file_durable_chirho` and
//! `create_dir_all`, because persisting a signed, sequenced evidence record IS a canary's job.
//!
//! A token-level predicate cannot express "mutates authority" versus "durably records its own
//! observation" — both are a file write. So this guard splits the question:
//!
//!   AUTHORITY MUTATION  appending to the authority log, moving refs, committing heads. A canary
//!                       doing any of these has stopped observing and started deciding. FORBIDDEN.
//!   OWN-EVIDENCE WRITE  `write_file_durable_chirho`, `create_dir_all` and friends, used to persist
//!                       the canary's own signed evidence record and head. PERMITTED, and the
//!                       reason the original detector could never be wired as written.
//!
//! THE CORPUS IS THE CLAIM. This guard proves the property for the two canary implementations named
//! below and for nothing else. A canary added elsewhere is outside this claim until it is added
//! here — stated so a green run is not read as "no canary mutates authority anywhere".

use crate::source_scan_chirho::{production_text_chirho, workspace_root_chirho};
use std::collections::BTreeSet;
use syn::visit::Visit;

/// The canary implementations this guard covers.
const CANARY_SOURCES_CHIRHO: &[&str] = &[
    "crates/support-chirho/cairn-writer-elector-chirho/src/shadow_canary_chirho.rs",
    "crates/ledger-chirho/cairn-ledger-composition-chirho/src/composition_chirho.rs",
];

/// Calls that MUTATE the authority a canary is supposed to be watching. Appending to the authority
/// log, moving a branch, or committing a head are decisions, not observations.
const AUTHORITY_MUTATION_TOKENS_CHIRHO: &[&str] = &[
    "append_gate1_authority_record_chirho(",
    "recover_gate1_authority_head_chirho(",
    "append_gate1_ring_a_anchors_chirho(",
    "append_gate1_anchor_for_family_chirho(",
    "append_gate1_ledger_anchor_chirho(",
    "append_jsonl",
    "append_recovered_jsonl",
    "append_serialized_jsonl",
    "commit_head_chirho(",
    "with_head_commit_chirho(",
    "set_branch_chirho(",
    "remove_branch_chirho(",
];

fn canary_production_text_chirho(rel_path_chirho: &str) -> String {
    let path_chirho = workspace_root_chirho().join(rel_path_chirho);
    let text_chirho = std::fs::read_to_string(&path_chirho)
        .unwrap_or_else(|e_chirho| panic!("read {}: {e_chirho}", path_chirho.display()));
    production_text_chirho(&text_chirho).into_owned()
}

fn authority_mutation_sites_in_text_chirho(text_chirho: &str) -> Vec<String> {
    AUTHORITY_MUTATION_TOKENS_CHIRHO
        .iter()
        .filter(|token_chirho| text_chirho.contains(**token_chirho))
        .map(|token_chirho| (*token_chirho).to_string())
        .collect()
}

#[test]
fn canaries_do_not_mutate_the_authority_they_watch_chirho() {
    for source_chirho in CANARY_SOURCES_CHIRHO {
        let text_chirho = canary_production_text_chirho(source_chirho);
        assert!(
            text_chirho.len() > 500,
            "{source_chirho} read back nearly empty — this guard would pass vacuously"
        );
        let sites_chirho = authority_mutation_sites_in_text_chirho(&text_chirho);
        assert!(
            sites_chirho.is_empty(),
            "canary {source_chirho} mutates the authority it watches: {sites_chirho:?}. A canary \
             records what it observed; appending to the authority log, moving a ref, or committing \
             a head makes it a participant in the decision it is supposed to be independent \
             evidence about. Persisting its OWN signed evidence is fine and is deliberately not \
             forbidden here — if this fired on an evidence write, the token belongs in the \
             permitted class, not in the forbidden one"
        );
    }
}

#[test]
fn own_evidence_writes_stay_permitted_chirho() {
    // The whole reason the original detector could not be wired. The shadow canary durably writes
    // its signed evidence record and head; that MUST NOT trip this guard, or the guard is unusable
    // and gets disabled — which protects nothing.
    let text_chirho = canary_production_text_chirho(CANARY_SOURCES_CHIRHO[0]);
    assert!(
        text_chirho.contains("write_file_durable_chirho(") || text_chirho.contains("create_dir_all("),
        "expected the shadow canary to still perform its own evidence writes; if it no longer does, \
         this test is measuring nothing and the permitted/forbidden split needs revisiting"
    );
    assert!(
        authority_mutation_sites_in_text_chirho(&text_chirho).is_empty(),
        "own-evidence writes must not be classified as authority mutation"
    );
}

#[test]
fn positive_control_the_forbidden_tokens_actually_fire_chirho() {
    // A guard whose green cannot be distinguished from a broken detector is decoration. Each
    // forbidden token must be caught in a known-true sample.
    for token_chirho in AUTHORITY_MUTATION_TOKENS_CHIRHO {
        let sample_chirho = format!("fn rogue_canary_chirho() {{ {token_chirho}root_chirho); }}");
        let sites_chirho = authority_mutation_sites_in_text_chirho(&sample_chirho);
        assert!(
            sites_chirho.contains(&(*token_chirho).to_string()),
            "forbidden token {token_chirho} failed its own positive control"
        );
    }
    // And a canary-shaped body doing only evidence writes must come back CLEAN, or the guard would
    // fire on every real canary.
    let evidence_only_chirho =
        "fn observe_chirho() { std::fs::create_dir_all(d); write_file_durable_chirho(p, b); }";
    assert!(
        authority_mutation_sites_in_text_chirho(evidence_only_chirho).is_empty(),
        "an evidence-only canary body must not be flagged as authority mutation"
    );
}

#[derive(Default)]
struct ActivationEntropyVisitorChirho {
    os_rng_references_chirho: usize,
    fill_calls_chirho: usize,
}

impl<'ast_chirho> Visit<'ast_chirho> for ActivationEntropyVisitorChirho {
    fn visit_path(&mut self, path_chirho: &'ast_chirho syn::Path) {
        self.os_rng_references_chirho += path_chirho
            .segments
            .iter()
            .filter(|segment_chirho| segment_chirho.ident == "OsRng")
            .count();
        syn::visit::visit_path(self, path_chirho);
    }

    fn visit_expr_method_call(&mut self, call_chirho: &'ast_chirho syn::ExprMethodCall) {
        if call_chirho.method == "try_fill_bytes" {
            self.fill_calls_chirho += 1;
        }
        syn::visit::visit_expr_method_call(self, call_chirho);
    }
}

#[test]
fn activation_incarnation_is_minted_inside_the_production_creator_chirho() {
    let relative_chirho = "crates/support-chirho/cairn-writer-elector-chirho/src/\
shadow_canary_activation_anchor_chirho.rs";
    let raw_source_chirho = std::fs::read_to_string(workspace_root_chirho().join(relative_chirho))
        .expect("read activation-anchor production source");
    let raw_syntax_chirho =
        syn::parse_file(&raw_source_chirho).expect("parse raw activation-anchor source");
    let fixed_creator_chirho = raw_syntax_chirho
        .items
        .iter()
        .find_map(|item_chirho| match item_chirho {
            syn::Item::Fn(function_chirho)
                if function_chirho.sig.ident
                    == "create_new_shadow_canary_activation_anchor_with_fixed_entropy_chirho" =>
            {
                Some(function_chirho)
            }
            _ => None,
        })
        .expect("fixed-entropy test creator");
    assert!(
        fixed_creator_chirho.attrs.iter().any(|attribute_chirho| {
            matches!(
                &attribute_chirho.meta,
                syn::Meta::List(list_chirho)
                    if list_chirho.path.is_ident("cfg")
                        && list_chirho.tokens.to_string() == "test"
            )
        }),
        "fixed entropy must remain cfg(test)-only"
    );
    let source_chirho = production_text_chirho(&raw_source_chirho);
    let syntax_chirho = syn::parse_file(&source_chirho).expect("parse activation-anchor source");
    let input_fields_chirho = syntax_chirho
        .items
        .iter()
        .find_map(|item_chirho| match item_chirho {
            syn::Item::Struct(struct_chirho)
                if struct_chirho.ident == "ShadowCanaryActivationAnchorInputChirho" =>
            {
                Some(
                    struct_chirho
                        .fields
                        .iter()
                        .map(|field_chirho| {
                            field_chirho
                                .ident
                                .as_ref()
                                .expect("named activation-anchor input field")
                                .to_string()
                        })
                        .collect::<BTreeSet<_>>(),
                )
            }
            _ => None,
        })
        .expect("activation-anchor input struct");
    assert_eq!(
        input_fields_chirho,
        BTreeSet::from([
            "activation_append_cut_chirho".to_owned(),
            "activation_authorization_digest_chirho".to_owned(),
            "activation_plan_digest_chirho".to_owned(),
            "resident_identity_digest_chirho".to_owned(),
        ]),
        "the caller may supply activation facts, never the incarnation entropy"
    );
    let creator_chirho = syntax_chirho
        .items
        .iter()
        .find_map(|item_chirho| match item_chirho {
            syn::Item::Fn(function_chirho)
                if function_chirho.sig.ident
                    == "create_new_shadow_canary_activation_anchor_chirho" =>
            {
                Some(function_chirho)
            }
            _ => None,
        })
        .expect("production activation-anchor creator");
    let mut visitor_chirho = ActivationEntropyVisitorChirho::default();
    visitor_chirho.visit_block(&creator_chirho.block);
    assert_eq!(visitor_chirho.os_rng_references_chirho, 1);
    assert_eq!(visitor_chirho.fill_calls_chirho, 1);
}
