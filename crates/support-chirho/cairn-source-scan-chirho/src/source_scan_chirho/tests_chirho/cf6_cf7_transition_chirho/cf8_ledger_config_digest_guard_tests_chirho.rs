// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)
//! Keeps every composed ledger-host startup on externally reviewed config bytes.
//!
//! Behavioral tests prove that a stale digest refuses before parsing and that a same-owner root
//! repoint touches neither root. This guard owns the refactor boundary those arms cannot census:
//! every current serving/reopen function must pass its caller-supplied expected digest to the strict
//! loader before it derives a root identity or opens authority, and the permissive loader remains
//! confined to named non-serving report, authoring, drill-layout, and pre-genesis plan roads. It also
//! pins one more setup call order no behavioral arm reaches without a database: a reviewed payer is
//! registered only after regenesis (C1 A3).

use crate::source_scan_chirho::{
    production_text_chirho, workspace_production_rs_files_chirho, workspace_root_chirho,
};
use std::collections::BTreeSet;
use syn::visit::{self, Visit};
use syn::{Expr, Item, ItemFn, Member, Pat, Stmt};

const RUNTIME_CLI_PATH_CHIRHO: &str =
    "crates/cairn-cli-chirho/src/cli_helpers_chirho/operations_chirho/runtime_cli_chirho.rs";
const GEO_NODE_PATH_CHIRHO: &str = "crates/ledger-chirho/cairn-ledger-geo-node-chirho/src/lib.rs";
const GEO_REPORT_PATH_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-geo-node-chirho/src/a6_authority_composition_chirho.rs";
const SMOKE_SETUP_PATH_CHIRHO: &str =
    "crates/services-chirho/cairn-operator-smoke-chirho/src/credits_demo_smoke_chirho/setup_chirho.rs";
const SMOKE_CONTINUATION_PATH_CHIRHO: &str =
    "crates/services-chirho/cairn-operator-smoke-chirho/src/credits_demo_smoke_chirho/continuation_chirho.rs";
const SMOKE_WIRE_PATH_CHIRHO: &str =
    "crates/services-chirho/cairn-operator-smoke-chirho/src/credits_demo_smoke_chirho/wire_smoke_chirho.rs";
const SMOKE_EVIDENCE_PATH_CHIRHO: &str =
    "crates/services-chirho/cairn-operator-smoke-chirho/src/credits_demo_smoke_chirho/evidence_chirho.rs";

const STRICT_LOADER_CHIRHO: &str = "load_digest_bound_config_chirho";
const PERMISSIVE_LOADER_CHIRHO: &str = "load_config_chirho";

#[derive(Clone, Copy)]
enum ExpectedDigestSourceChirho {
    IdentChirho(&'static str),
    FieldChirho {
        base_chirho: &'static str,
        field_chirho: &'static str,
    },
}

#[derive(Debug)]
struct CallObservationChirho {
    name_chirho: String,
    strict_expected_source_matches_chirho: Option<bool>,
}

#[derive(Default)]
struct CallOrderVisitorChirho {
    calls_chirho: Vec<CallObservationChirho>,
    expected_source_chirho: Option<ExpectedDigestSourceChirho>,
}

fn peeled_expression_chirho(mut expression_chirho: &Expr) -> &Expr {
    loop {
        expression_chirho = match expression_chirho {
            Expr::Group(group_chirho) => &group_chirho.expr,
            Expr::Paren(paren_chirho) => &paren_chirho.expr,
            Expr::Reference(reference_chirho) => &reference_chirho.expr,
            _ => return expression_chirho,
        };
    }
}

fn path_is_chirho(expression_chirho: &Expr, ident_chirho: &str) -> bool {
    matches!(
        peeled_expression_chirho(expression_chirho),
        Expr::Path(path_chirho) if path_chirho.path.is_ident(ident_chirho)
    )
}

fn expected_source_matches_chirho(
    expression_chirho: &Expr,
    expected_chirho: ExpectedDigestSourceChirho,
) -> bool {
    match expected_chirho {
        ExpectedDigestSourceChirho::IdentChirho(ident_chirho) => {
            path_is_chirho(expression_chirho, ident_chirho)
        }
        ExpectedDigestSourceChirho::FieldChirho {
            base_chirho,
            field_chirho,
        } => matches!(
            peeled_expression_chirho(expression_chirho),
            Expr::Field(field_expression_chirho)
                if path_is_chirho(&field_expression_chirho.base, base_chirho)
                    && matches!(
                        &field_expression_chirho.member,
                        Member::Named(member_chirho) if member_chirho == field_chirho
                    )
        ),
    }
}

fn called_path_name_chirho(expression_chirho: &Expr) -> Option<String> {
    let Expr::Path(path_chirho) = peeled_expression_chirho(expression_chirho) else {
        return None;
    };
    path_chirho
        .path
        .segments
        .last()
        .map(|segment_chirho| segment_chirho.ident.to_string())
}

impl<'ast_chirho> Visit<'ast_chirho> for CallOrderVisitorChirho {
    fn visit_expr_call(&mut self, call_chirho: &'ast_chirho syn::ExprCall) {
        // Record after visiting arguments so the trace follows Rust evaluation order. This matters
        // when a future composer nests an authority opener inside another call.
        visit::visit_expr_call(self, call_chirho);
        let Some(name_chirho) = called_path_name_chirho(&call_chirho.func) else {
            return;
        };
        let strict_expected_source_matches_chirho =
            (name_chirho == STRICT_LOADER_CHIRHO).then(|| {
                call_chirho
                    .args
                    .iter()
                    .nth(1)
                    .is_some_and(|argument_chirho| {
                        self.expected_source_chirho.is_some_and(|expected_chirho| {
                            expected_source_matches_chirho(argument_chirho, expected_chirho)
                        })
                    })
            });
        self.calls_chirho.push(CallObservationChirho {
            strict_expected_source_matches_chirho,
            name_chirho,
        });
    }

    fn visit_expr_method_call(&mut self, call_chirho: &'ast_chirho syn::ExprMethodCall) {
        visit::visit_expr_method_call(self, call_chirho);
        self.calls_chirho.push(CallObservationChirho {
            name_chirho: call_chirho.method.to_string(),
            strict_expected_source_matches_chirho: None,
        });
    }
}

impl CallOrderVisitorChirho {
    fn with_expected_source_chirho(expected_chirho: ExpectedDigestSourceChirho) -> Self {
        Self {
            expected_source_chirho: Some(expected_chirho),
            ..Self::default()
        }
    }
}

fn parse_source_chirho(path_chirho: &str) -> syn::File {
    let full_path_chirho = workspace_root_chirho().join(path_chirho);
    let source_chirho = std::fs::read_to_string(&full_path_chirho).unwrap_or_else(|error_chirho| {
        panic!("read {}: {error_chirho}", full_path_chirho.display())
    });
    syn::parse_file(&production_text_chirho(&source_chirho))
        .unwrap_or_else(|error_chirho| panic!("parse {path_chirho}: {error_chirho}"))
}

fn function_chirho<'a>(file_chirho: &'a syn::File, name_chirho: &str) -> &'a ItemFn {
    file_chirho
        .items
        .iter()
        .find_map(|item_chirho| match item_chirho {
            Item::Fn(function_chirho) if function_chirho.sig.ident == name_chirho => {
                Some(function_chirho)
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("function `{name_chirho}` is absent from the guarded source"))
}

fn up_arm_chirho(function_chirho: &ItemFn) -> &Expr {
    let match_chirho = function_chirho
        .block
        .stmts
        .iter()
        .find_map(|statement_chirho| match statement_chirho {
            Stmt::Expr(Expr::Match(match_chirho), _) => Some(match_chirho),
            _ => None,
        })
        .expect("runtime command handler must contain its command match");
    match_chirho
        .arms
        .iter()
        .find_map(|arm_chirho| match &arm_chirho.pat {
            Pat::TupleStruct(pattern_chirho)
                if pattern_chirho
                    .path
                    .segments
                    .last()
                    .is_some_and(|segment_chirho| segment_chirho.ident == "UpChirho") =>
            {
                Some(arm_chirho.body.as_ref())
            }
            _ => None,
        })
        .expect("runtime command handler must carry the UpChirho arm")
}

fn assert_digest_before_hazards_chirho(
    label_chirho: &str,
    expected_chirho: ExpectedDigestSourceChirho,
    visit_chirho: impl FnOnce(&mut CallOrderVisitorChirho),
    hazards_chirho: &[&str],
) {
    let mut visitor_chirho = CallOrderVisitorChirho::with_expected_source_chirho(expected_chirho);
    visit_chirho(&mut visitor_chirho);

    let strict_calls_chirho: Vec<_> = visitor_chirho
        .calls_chirho
        .iter()
        .enumerate()
        .filter(|(_index_chirho, call_chirho)| call_chirho.name_chirho == STRICT_LOADER_CHIRHO)
        .collect();
    assert_eq!(
        strict_calls_chirho.len(),
        1,
        "{label_chirho} must call the strict digest-bound config loader exactly once"
    );
    let (strict_index_chirho, strict_call_chirho) = strict_calls_chirho[0];
    assert_eq!(
        strict_call_chirho.strict_expected_source_matches_chirho,
        Some(true),
        "{label_chirho} must compare against its externally supplied expected digest, never a digest derived beside the config"
    );
    assert!(
        !visitor_chirho
            .calls_chirho
            .iter()
            .any(|call_chirho| call_chirho.name_chirho == PERMISSIVE_LOADER_CHIRHO),
        "{label_chirho} must not retain a permissive config parse beside the strict load"
    );

    for hazard_chirho in hazards_chirho {
        let hazard_indexes_chirho: Vec<_> = visitor_chirho
            .calls_chirho
            .iter()
            .enumerate()
            .filter(|(_index_chirho, call_chirho)| call_chirho.name_chirho == *hazard_chirho)
            .map(|(index_chirho, _call_chirho)| index_chirho)
            .collect();
        assert!(
            !hazard_indexes_chirho.is_empty(),
            "{label_chirho} no longer contains guarded operation `{hazard_chirho}`; re-point this guard at the replacement authority/root operation"
        );
        assert!(
            hazard_indexes_chirho
                .iter()
                .all(|hazard_index_chirho| *hazard_index_chirho > strict_index_chirho),
            "{label_chirho} reaches `{hazard_chirho}` before authenticating the exact reviewed config bytes"
        );
    }
}

#[test]
fn every_composed_startup_authenticates_external_config_bytes_before_authority_chirho() {
    let runtime_chirho = parse_source_chirho(RUNTIME_CLI_PATH_CHIRHO);
    let runtime_handler_chirho = function_chirho(&runtime_chirho, "handle_runtime_command_chirho");
    let up_chirho = up_arm_chirho(runtime_handler_chirho);
    assert_digest_before_hazards_chirho(
        "cairn-chirho up",
        ExpectedDigestSourceChirho::IdentChirho("expected_config_digest_chirho"),
        |visitor_chirho| visitor_chirho.visit_expr(up_chirho),
        &[
            "tenant_id_with_fallback_chirho",
            "root_for_tenant_chirho",
            "serve_resident_gd7_voter_geo_node_chirho",
            "open_existing_chirho",
            "open_shared_ledger_host_postgres_effect_runtime_chirho",
        ],
    );
    let runtime_open_chirho = function_chirho(&runtime_chirho, "load_and_open_ledger_host_chirho");
    assert_digest_before_hazards_chirho(
        "shared CLI ledger-host opener",
        ExpectedDigestSourceChirho::IdentChirho("expected_config_digest_chirho"),
        |visitor_chirho| visitor_chirho.visit_item_fn(runtime_open_chirho),
        &["open_existing_chirho"],
    );

    let geo_chirho = parse_source_chirho(GEO_NODE_PATH_CHIRHO);
    for function_name_chirho in [
        "serve_resident_gd7_voter_geo_node_with_admission_chirho",
        "serve_resident_gd7_held_geo_node_chirho",
    ] {
        let function_chirho = function_chirho(&geo_chirho, function_name_chirho);
        assert_digest_before_hazards_chirho(
            function_name_chirho,
            ExpectedDigestSourceChirho::IdentChirho("expected_ledger_config_digest_chirho"),
            |visitor_chirho| visitor_chirho.visit_item_fn(function_chirho),
            &[
                "verify_cluster_node_file_config_custody_chirho",
                "load_cluster_node_file_config_chirho",
                "verify_host_ledger_config_custody_chirho",
                "open_existing_chirho",
            ],
        );
    }

    let setup_chirho = parse_source_chirho(SMOKE_SETUP_PATH_CHIRHO);
    let setup_function_chirho = function_chirho(&setup_chirho, "run_credits_demo_setup_chirho");
    assert_digest_before_hazards_chirho(
        "credits-demo setup",
        ExpectedDigestSourceChirho::FieldChirho {
            base_chirho: "inputs_chirho",
            field_chirho: "expected_config_digest_chirho",
        },
        |visitor_chirho| visitor_chirho.visit_item_fn(setup_function_chirho),
        &[
            "verify_host_ledger_config_custody_chirho",
            "canonicalize",
            "precheck_reviewed_payer_chirho",
            "register_reviewed_payer_chirho",
            "load_verified_identities_chirho",
            "run_ledger_regenesis_chirho",
            "open_resident_effect_journal_handle_chirho",
        ],
    );

    let continuation_chirho = parse_source_chirho(SMOKE_CONTINUATION_PATH_CHIRHO);
    let continuation_function_chirho =
        function_chirho(&continuation_chirho, "run_credits_demo_continuation_chirho");
    assert_digest_before_hazards_chirho(
        "credits-demo continuation",
        ExpectedDigestSourceChirho::IdentChirho("expected_config_digest_chirho"),
        |visitor_chirho| visitor_chirho.visit_item_fn(continuation_function_chirho),
        &["open_resident_effect_journal_handle_chirho"],
    );

    let wire_chirho = parse_source_chirho(SMOKE_WIRE_PATH_CHIRHO);
    for (function_name_chirho, hazards_chirho) in [
        ("open_host_chirho", &["open_existing_chirho"][..].as_ref()),
        (
            "open_pg_runtime_chirho",
            &["open_shared_ledger_host_postgres_effect_runtime_chirho"][..].as_ref(),
        ),
    ] {
        let function_chirho = function_chirho(&wire_chirho, function_name_chirho);
        assert_digest_before_hazards_chirho(
            function_name_chirho,
            ExpectedDigestSourceChirho::FieldChirho {
                base_chirho: "setup_chirho",
                field_chirho: "expected_config_digest_chirho",
            },
            |visitor_chirho| visitor_chirho.visit_item_fn(function_chirho),
            hazards_chirho,
        );
    }

    let evidence_chirho = parse_source_chirho(SMOKE_EVIDENCE_PATH_CHIRHO);
    let evidence_function_chirho =
        function_chirho(&evidence_chirho, "verify_ledger_substrate_chirho");
    assert_digest_before_hazards_chirho(
        "credits-demo evidence reopen",
        ExpectedDigestSourceChirho::FieldChirho {
            base_chirho: "setup_chirho",
            field_chirho: "expected_config_digest_chirho",
        },
        |visitor_chirho| visitor_chirho.visit_item_fn(evidence_function_chirho),
        &["open_existing_chirho"],
    );

    let report_chirho = parse_source_chirho(GEO_REPORT_PATH_CHIRHO);
    let report_function_chirho = function_chirho(
        &report_chirho,
        "configured_ledger_mirror_live_head_report_read_only_chirho",
    );
    assert_digest_before_hazards_chirho(
        "configured live-head report",
        ExpectedDigestSourceChirho::IdentChirho("expected_config_digest_chirho"),
        |visitor_chirho| visitor_chirho.visit_item_fn(report_function_chirho),
        &[
            "verify_host_ledger_config_custody_chirho",
            "canonicalize",
            "existing_keypair_pubkey_hex_chirho",
        ],
    );
}

#[derive(Default)]
struct LoaderCallerVisitorChirho {
    current_function_chirho: Option<String>,
    callers_chirho: BTreeSet<String>,
    loader_chirho: &'static str,
    path_chirho: String,
}

impl<'ast_chirho> Visit<'ast_chirho> for LoaderCallerVisitorChirho {
    fn visit_item_fn(&mut self, function_chirho: &'ast_chirho ItemFn) {
        let prior_chirho = self
            .current_function_chirho
            .replace(function_chirho.sig.ident.to_string());
        self.visit_block(&function_chirho.block);
        self.current_function_chirho = prior_chirho;
    }

    fn visit_impl_item_fn(&mut self, function_chirho: &'ast_chirho syn::ImplItemFn) {
        let prior_chirho = self
            .current_function_chirho
            .replace(function_chirho.sig.ident.to_string());
        self.visit_block(&function_chirho.block);
        self.current_function_chirho = prior_chirho;
    }

    fn visit_expr_call(&mut self, call_chirho: &'ast_chirho syn::ExprCall) {
        if called_path_name_chirho(&call_chirho.func).as_deref() == Some(self.loader_chirho) {
            self.callers_chirho.insert(format!(
                "{}::{}",
                self.path_chirho,
                self.current_function_chirho
                    .as_deref()
                    .unwrap_or("<outside-function-chirho>")
            ));
        }
        visit::visit_expr_call(self, call_chirho);
    }
}

fn production_loader_callers_chirho(loader_chirho: &'static str) -> (BTreeSet<String>, usize) {
    let root_chirho = workspace_root_chirho();
    let mut actual_chirho = BTreeSet::new();
    let mut parsed_subject_files_chirho = 0usize;
    for path_chirho in workspace_production_rs_files_chirho() {
        let raw_chirho = std::fs::read_to_string(&path_chirho).unwrap_or_else(|error_chirho| {
            panic!("read {}: {error_chirho}", path_chirho.display())
        });
        let production_chirho = production_text_chirho(&raw_chirho);
        if !production_chirho.contains(loader_chirho) {
            continue;
        }
        parsed_subject_files_chirho += 1;
        let relative_chirho = path_chirho
            .strip_prefix(&root_chirho)
            .expect("production source must remain inside this worktree")
            .to_string_lossy()
            .replace('\\', "/");
        let syntax_chirho = syn::parse_file(&production_chirho)
            .unwrap_or_else(|error_chirho| panic!("parse {relative_chirho}: {error_chirho}"));
        let mut visitor_chirho = LoaderCallerVisitorChirho {
            loader_chirho,
            path_chirho: relative_chirho,
            ..Default::default()
        };
        visitor_chirho.visit_file(&syntax_chirho);
        actual_chirho.extend(visitor_chirho.callers_chirho);
    }
    (actual_chirho, parsed_subject_files_chirho)
}

/// C1 A3 (Agy #29339, claude2 #29344): setup registers a reviewed payer only after regenesis. So every
/// read-only gate refuses before setup writes an identity, and so does regenesis's own validation.
/// `a_read_only_refusal_after_the_precheck_registers_nothing_chirho` proves the read-only half by
/// behavior. A registration moved between the authoring gate and regenesis would pass it, because
/// reaching regenesis needs a database. That gap is pinned here.
#[test]
fn credits_demo_setup_registers_a_reviewed_payer_only_after_regenesis_chirho() {
    let setup_chirho = parse_source_chirho(SMOKE_SETUP_PATH_CHIRHO);
    let mut visitor_chirho = CallOrderVisitorChirho::with_expected_source_chirho(
        ExpectedDigestSourceChirho::FieldChirho {
            base_chirho: "inputs_chirho",
            field_chirho: "expected_config_digest_chirho",
        },
    );
    visitor_chirho.visit_item_fn(function_chirho(
        &setup_chirho,
        "run_credits_demo_setup_chirho",
    ));
    let indexes_chirho = |name_chirho: &str| -> Vec<usize> {
        visitor_chirho
            .calls_chirho
            .iter()
            .enumerate()
            .filter(|(_index_chirho, call_chirho)| call_chirho.name_chirho == name_chirho)
            .map(|(index_chirho, _call_chirho)| index_chirho)
            .collect()
    };
    let regenesis_chirho = indexes_chirho("run_ledger_regenesis_chirho");
    let registrations_chirho = indexes_chirho("register_reviewed_payer_chirho");
    assert_eq!(
        regenesis_chirho.len(),
        1,
        "setup must run regenesis exactly once"
    );
    assert_eq!(
        registrations_chirho.len(),
        1,
        "setup must register a reviewed payer at exactly one site"
    );
    assert!(
        registrations_chirho[0] > regenesis_chirho[0],
        "setup registers a reviewed payer before regenesis, so a refusal there would leave the \
         identity behind on a root that can no longer be rerun"
    );
}

#[test]
fn strict_config_loader_caller_set_is_tree_wide_and_reviewed_chirho() {
    let (actual_chirho, parsed_subject_files_chirho) =
        production_loader_callers_chirho(STRICT_LOADER_CHIRHO);
    assert!(
        parsed_subject_files_chirho >= 7,
        "the strict-loader census found too little source to cover every composed startup"
    );
    let expected_chirho = BTreeSet::from([
        "crates/cairn-cli-chirho/src/cli_helpers_chirho/operations_chirho/runtime_cli_chirho.rs::handle_runtime_command_chirho".to_owned(),
        "crates/cairn-cli-chirho/src/cli_helpers_chirho/operations_chirho/runtime_cli_chirho.rs::load_and_open_ledger_host_chirho".to_owned(),
        "crates/ledger-chirho/cairn-ledger-geo-node-chirho/src/a6_authority_composition_chirho.rs::configured_ledger_mirror_live_head_report_read_only_chirho".to_owned(),
        "crates/ledger-chirho/cairn-ledger-geo-node-chirho/src/lib.rs::serve_resident_gd7_held_geo_node_chirho".to_owned(),
        "crates/ledger-chirho/cairn-ledger-geo-node-chirho/src/lib.rs::serve_resident_gd7_voter_geo_node_with_admission_chirho".to_owned(),
        "crates/services-chirho/cairn-operator-smoke-chirho/src/credits_demo_smoke_chirho/continuation_chirho.rs::run_credits_demo_continuation_chirho".to_owned(),
        "crates/services-chirho/cairn-operator-smoke-chirho/src/credits_demo_smoke_chirho/evidence_chirho.rs::verify_ledger_substrate_chirho".to_owned(),
        "crates/services-chirho/cairn-operator-smoke-chirho/src/credits_demo_smoke_chirho/setup_chirho.rs::run_credits_demo_setup_chirho".to_owned(),
        "crates/services-chirho/cairn-operator-smoke-chirho/src/credits_demo_smoke_chirho/wire_smoke_chirho.rs::open_host_chirho".to_owned(),
        "crates/services-chirho/cairn-operator-smoke-chirho/src/credits_demo_smoke_chirho/wire_smoke_chirho.rs::open_pg_runtime_chirho".to_owned(),
    ]);
    assert_eq!(
        actual_chirho, expected_chirho,
        "the strict config loader's production caller set changed. A new caller must join the named positive population and prove that its expected digest arrives from an external argument rather than being derived beside the config."
    );
}

#[test]
fn permissive_config_loading_stays_out_of_every_serving_composer_chirho() {
    let (actual_chirho, parsed_subject_files_chirho) =
        production_loader_callers_chirho(PERMISSIVE_LOADER_CHIRHO);
    assert!(
        parsed_subject_files_chirho >= 6,
        "the permissive-loader census found too little source to make its absence claims credible"
    );

    let expected_chirho = BTreeSet::from([
        "crates/authoring-chirho/cairn-tenant-placement-author-chirho/src/authoring_chirho.rs::verify_runtime_activation_lineage_chirho".to_owned(),
        "crates/ledger-chirho/cairn-drill-root-layout-chirho/src/lib.rs::validate_item6_drill_root_layout_chirho".to_owned(),
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/shadow_canary_report_chirho.rs::configured_shadow_canary_report_read_only_chirho".to_owned(),
        "crates/ledger-chirho/cairn-ledger-regenesis-chirho/src/plan_chirho.rs::load_verified_plan_chirho".to_owned(),
        "src/operator_flows_chirho/ops_custody_chirho.rs::config_posture_chirho".to_owned(),
    ]);
    assert_eq!(
        actual_chirho, expected_chirho,
        "the permissive config loader's production caller set changed. These five callers are bounded non-serving report, authoring, drill-layout, and pre-genesis plan roads. Any serving/reopen caller must take an externally reviewed digest and use `{STRICT_LOADER_CHIRHO}`; any new non-serving caller still requires an explicit review here."
    );
}
