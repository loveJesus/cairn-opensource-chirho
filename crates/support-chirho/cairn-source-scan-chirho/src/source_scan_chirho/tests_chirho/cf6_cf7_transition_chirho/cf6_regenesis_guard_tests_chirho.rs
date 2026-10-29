// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::{production_text_chirho, workspace_production_rs_files_chirho, workspace_root_chirho};
use std::collections::{BTreeMap, BTreeSet};
use syn::visit::Visit;

/// Shared with the sibling signer-fence guard, which reasons about the same crate. One home for the
/// path so the two guards can never disagree about which crate they are guarding.
pub(super) const REGENESIS_CRATE_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-regenesis-chirho";
const GUARDED_COMPENSATION_DOORS_CHIRHO: [&str; 4] = [
    "mint_verified_current_undo_plan_authority_chirho",
    "preview_current_ledger_host_postgres_compensation_chirho",
    "execute_current_ledger_host_postgres_compensation_chirho",
    "execute_compensation_chirho",
];

fn guarded_compensation_name_chirho(name_chirho: &str) -> bool {
    GUARDED_COMPENSATION_DOORS_CHIRHO.contains(&name_chirho)
}

/// Shared with the sibling signer-fence guard for the same reason: two copies of "is this item
/// test-only" could drift, and a drifted copy would silently widen or narrow a production census.
pub(super) fn attributes_are_test_only_chirho(attributes_chirho: &[syn::Attribute]) -> bool {
    attributes_chirho.iter().any(|attribute_chirho| {
        let syn::Meta::List(list_chirho) = &attribute_chirho.meta else {
            return false;
        };
        attribute_chirho.path().is_ident("cfg")
            && list_chirho
                .tokens
                .to_string()
                .split(|character_chirho: char| !character_chirho.is_ascii_alphanumeric())
                .any(|token_chirho| token_chirho == "test")
    })
}

fn use_tree_renames_guarded_compensation_chirho(tree_chirho: &syn::UseTree) -> bool {
    match tree_chirho {
        syn::UseTree::Rename(rename_chirho) => {
            guarded_compensation_name_chirho(&rename_chirho.ident.to_string())
        }
        syn::UseTree::Path(path_chirho) => {
            use_tree_renames_guarded_compensation_chirho(&path_chirho.tree)
        }
        syn::UseTree::Group(group_chirho) => group_chirho
            .items
            .iter()
            .any(use_tree_renames_guarded_compensation_chirho),
        syn::UseTree::Name(_) | syn::UseTree::Glob(_) => false,
    }
}

struct CompensationCallerVisitorChirho<'a> {
    file_chirho: &'a str,
    current_function_chirho: Option<String>,
    calls_chirho: &'a mut BTreeMap<String, BTreeSet<String>>,
    forbidden_indirections_chirho: &'a mut Vec<String>,
}

impl CompensationCallerVisitorChirho<'_> {
    fn record_call_chirho(&mut self, name_chirho: &str) {
        let function_chirho = self
            .current_function_chirho
            .as_deref()
            .unwrap_or("<outside-function-chirho>");
        self.calls_chirho
            .entry(name_chirho.to_owned())
            .or_default()
            .insert(format!("{}::{function_chirho}", self.file_chirho));
    }

    fn guarded_name_from_call_chirho(call_chirho: &syn::Expr) -> Option<String> {
        let syn::Expr::Path(path_chirho) = call_chirho else {
            return None;
        };
        let name_chirho = path_chirho.path.segments.last()?.ident.to_string();
        guarded_compensation_name_chirho(&name_chirho).then_some(name_chirho)
    }
}

impl<'ast_chirho> Visit<'ast_chirho> for CompensationCallerVisitorChirho<'_> {
    fn visit_item_fn(&mut self, function_chirho: &'ast_chirho syn::ItemFn) {
        if attributes_are_test_only_chirho(&function_chirho.attrs) {
            return;
        }
        let prior_chirho = self
            .current_function_chirho
            .replace(function_chirho.sig.ident.to_string());
        self.visit_block(&function_chirho.block);
        self.current_function_chirho = prior_chirho;
    }

    fn visit_impl_item_fn(&mut self, function_chirho: &'ast_chirho syn::ImplItemFn) {
        if attributes_are_test_only_chirho(&function_chirho.attrs) {
            return;
        }
        let prior_chirho = self
            .current_function_chirho
            .replace(function_chirho.sig.ident.to_string());
        self.visit_block(&function_chirho.block);
        self.current_function_chirho = prior_chirho;
    }

    fn visit_item_mod(&mut self, module_chirho: &'ast_chirho syn::ItemMod) {
        if attributes_are_test_only_chirho(&module_chirho.attrs) {
            return;
        }
        syn::visit::visit_item_mod(self, module_chirho);
    }

    fn visit_item_impl(&mut self, implementation_chirho: &'ast_chirho syn::ItemImpl) {
        if attributes_are_test_only_chirho(&implementation_chirho.attrs) {
            return;
        }
        syn::visit::visit_item_impl(self, implementation_chirho);
    }

    fn visit_expr_call(&mut self, call_chirho: &'ast_chirho syn::ExprCall) {
        if let Some(name_chirho) = Self::guarded_name_from_call_chirho(&call_chirho.func) {
            self.record_call_chirho(&name_chirho);
            for argument_chirho in &call_chirho.args {
                self.visit_expr(argument_chirho);
            }
            return;
        }
        syn::visit::visit_expr_call(self, call_chirho);
    }

    fn visit_expr_method_call(&mut self, call_chirho: &'ast_chirho syn::ExprMethodCall) {
        let name_chirho = call_chirho.method.to_string();
        if guarded_compensation_name_chirho(&name_chirho) {
            self.record_call_chirho(&name_chirho);
        }
        syn::visit::visit_expr_method_call(self, call_chirho);
    }

    fn visit_expr_path(&mut self, path_chirho: &'ast_chirho syn::ExprPath) {
        if let Some(name_chirho) = path_chirho
            .path
            .segments
            .last()
            .map(|segment_chirho| segment_chirho.ident.to_string())
        {
            if guarded_compensation_name_chirho(&name_chirho) {
                self.forbidden_indirections_chirho.push(format!(
                    "{}: non-call reference to {name_chirho}",
                    self.file_chirho
                ));
                return;
            }
        }
        syn::visit::visit_expr_path(self, path_chirho);
    }

    fn visit_item_use(&mut self, use_chirho: &'ast_chirho syn::ItemUse) {
        if use_tree_renames_guarded_compensation_chirho(&use_chirho.tree) {
            self.forbidden_indirections_chirho.push(format!(
                "{}: renamed compensation-authority import",
                self.file_chirho
            ));
        }
        syn::visit::visit_item_use(self, use_chirho);
    }

    fn visit_macro(&mut self, macro_chirho: &'ast_chirho syn::Macro) {
        let tokens_chirho = macro_chirho.tokens.to_string();
        if let Some(name_chirho) = GUARDED_COMPENSATION_DOORS_CHIRHO
            .iter()
            .find(|name_chirho| tokens_chirho.contains(**name_chirho))
        {
            self.forbidden_indirections_chirho.push(format!(
                "{}: macro token stream names {name_chirho}",
                self.file_chirho
            ));
            return;
        }
        syn::visit::visit_macro(self, macro_chirho);
    }
}

struct AuthorityConstructionVisitorChirho {
    current_function_chirho: Option<String>,
    constructors_chirho: BTreeSet<String>,
}

impl<'ast_chirho> Visit<'ast_chirho> for AuthorityConstructionVisitorChirho {
    fn visit_item_fn(&mut self, function_chirho: &'ast_chirho syn::ItemFn) {
        if attributes_are_test_only_chirho(&function_chirho.attrs) {
            return;
        }
        let prior_chirho = self
            .current_function_chirho
            .replace(function_chirho.sig.ident.to_string());
        self.visit_block(&function_chirho.block);
        self.current_function_chirho = prior_chirho;
    }

    fn visit_impl_item_fn(&mut self, function_chirho: &'ast_chirho syn::ImplItemFn) {
        if attributes_are_test_only_chirho(&function_chirho.attrs) {
            return;
        }
        let prior_chirho = self
            .current_function_chirho
            .replace(function_chirho.sig.ident.to_string());
        self.visit_block(&function_chirho.block);
        self.current_function_chirho = prior_chirho;
    }

    fn visit_item_mod(&mut self, module_chirho: &'ast_chirho syn::ItemMod) {
        if attributes_are_test_only_chirho(&module_chirho.attrs) {
            return;
        }
        syn::visit::visit_item_mod(self, module_chirho);
    }

    fn visit_item_impl(&mut self, implementation_chirho: &'ast_chirho syn::ItemImpl) {
        if attributes_are_test_only_chirho(&implementation_chirho.attrs) {
            return;
        }
        syn::visit::visit_item_impl(self, implementation_chirho);
    }

    fn visit_expr_struct(&mut self, expression_chirho: &'ast_chirho syn::ExprStruct) {
        if expression_chirho
            .path
            .segments
            .last()
            .is_some_and(|segment_chirho| {
                segment_chirho.ident == "VerifiedCurrentUndoPlanAuthorityChirho"
            })
        {
            self.constructors_chirho.insert(
                self.current_function_chirho
                    .clone()
                    .unwrap_or_else(|| "<outside-function-chirho>".to_owned()),
            );
        }
        syn::visit::visit_expr_struct(self, expression_chirho);
    }
}

#[test]
fn serve_runtime_cannot_compile_against_regenesis_authority_chirho() {
    let root_chirho = workspace_root_chirho();
    let serve_manifest_chirho =
        std::fs::read_to_string(root_chirho.join("crates/cairn-serve-runtime-chirho/Cargo.toml"))
            .unwrap();
    assert!(
        !serve_manifest_chirho.contains("cairn-ledger-regenesis-chirho"),
        "serve runtime must remain structurally unable to compile against create authority"
    );
    let regenesis_manifest_chirho =
        std::fs::read_to_string(root_chirho.join(REGENESIS_CRATE_CHIRHO).join("Cargo.toml"))
            .unwrap();
    assert!(
        !regenesis_manifest_chirho.contains("cairn-serve-runtime-chirho"),
        "H3-A must not pull the served application surface into operator provisioning"
    );
}

#[test]
fn regenesis_operator_source_has_no_ambient_or_generated_key_road_chirho() {
    let source_root_chirho = workspace_root_chirho()
        .join(REGENESIS_CRATE_CHIRHO)
        .join("src");
    let mut files_chirho = std::fs::read_dir(&source_root_chirho)
        .unwrap()
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap();
    files_chirho.sort_by_key(|entry_chirho| entry_chirho.file_name());
    let mut production_source_chirho = String::new();
    for entry_chirho in files_chirho {
        let path_chirho = entry_chirho.path();
        if path_chirho
            .extension()
            .and_then(|value_chirho| value_chirho.to_str())
            == Some("rs")
        {
            let source_chirho = std::fs::read_to_string(path_chirho).unwrap();
            production_source_chirho.push_str(&production_text_chirho(&source_chirho));
        }
    }
    // Positive controls. The crate really does build ed25519 signing keys from EXISTING secret
    // bytes, so the absence list below is a statement about live crypto code rather than an empty
    // scan that would read just as green over source this walker never actually gathered.
    assert!(
        production_source_chirho.contains("SigningKey"),
        "operator regenesis production source must actually use ed25519 signing keys \
         (positive control — a green absence scan over source with no keys proves nothing)"
    );
    assert!(
        production_source_chirho.contains("from_bytes"),
        "operator regenesis production source must load keys via from_bytes (positive control)"
    );

    // `thread_rng`, `::generate`, and `from_entropy` are here because the geo-genesis sibling census
    // already forbids them and this one did not: `rand_core` is feature-unified across the
    // workspace, so ed25519-dalek's generator is reachable from this crate whether or not it
    // declares an RNG edge, and a name-shaped hole in a never-generate census is a hole in the only
    // enforcement there is. Compile-time gating cannot close it; this census is the guarantee.
    for forbidden_chirho in [
        "std::env::",
        "OsRng",
        "thread_rng",
        "::generate",
        "from_entropy",
        "set_secret_chirho(",
        "cairn_serve_runtime_chirho",
    ] {
        assert!(
            !production_source_chirho.contains(forbidden_chirho),
            "operator regenesis source gained forbidden ambient/create road: {forbidden_chirho}"
        );
    }

    // And refuse a direct RNG dependency edge, for the same reason the geo sibling does: a declared
    // edge would make a generator ordinary rather than exceptional.
    let manifest_chirho = std::fs::read_to_string(
        workspace_root_chirho()
            .join(REGENESIS_CRATE_CHIRHO)
            .join("Cargo.toml"),
    )
    .unwrap();
    let dependency_names_chirho =
        super::geo_genesis_guard_tests_chirho::manifest_dependency_names_chirho(&manifest_chirho);
    assert!(
        dependency_names_chirho
            .iter()
            .any(|name_chirho| name_chirho == "ed25519-dalek"),
        "manifest dependency parse returned nothing recognizable (positive control): a wrongly \
         parsed or empty list would make the RNG-edge check below silently vacuous"
    );
    for forbidden_chirho in ["rand", "rand_core", "rand-core"] {
        assert!(
            !dependency_names_chirho
                .iter()
                .any(|name_chirho| name_chirho == forbidden_chirho),
            "operator regenesis gained an RNG dependency edge that could enable key generation: \
             {forbidden_chirho}"
        );
    }
}

/// The brick-#3 structural closure, guarded so it cannot be silently reopened.
///
/// Brick #2 recorded honestly that a pin from its two thin derivation wrappers was well-formed and
/// UN-VOUCHED: nothing stopped a caller deriving artifacts with no custody proof. Brick #3 closed
/// that at the SIGNATURE — each derivation now requires the loaded runtime signers — and at the
/// crate boundary, by exporting the custody-bound road alone. Both halves matter: widening the
/// exports again would hand an un-vouched shape back to callers even though the signature still
/// asks for custody.
///
/// The dropped clause is the point of this note, and it has since become TRUE — for callers outside
/// `cairn-ledger-host-chirho`, which is every caller this guard reasons about. This guard used to
/// say the derivations require the loaded runtime signers "which only
/// `HostLedgerSignersChirho::load_existing_chirho` can produce". That clause was FALSE when it was
/// dropped: the type's six fields were `pub` and it was not `#[non_exhaustive]`, so any crate could
/// re-assemble the set by struct literal, splicing one role in from a different root. The seal brick
/// made those fields `pub(crate)` with per-role shared-borrow accessors, so a foreign crate can no
/// longer write the literal or assign a field. The clause still does not come back into this guard's
/// text, for the same reason it left and one more: the assertions here are about the SIGNATURE and
/// the EXPORTS, which is what does the work, and the seal's remaining residual is in-crate, so the
/// sealed claim is about foreign crates rather than universal.
///
/// The type-level property stays pinned where it can EXECUTE rather than becoming a text assertion
/// here — a text guard reading a neighbouring crate's source could only match on the word `pub`.
/// It is pinned by two `compile_fail` doctests on the type itself, which now prove both re-assembly
/// routes are rejected across the crate boundary and carry the migration path for a red.
#[test]
fn regenesis_pin_derivation_is_custody_bound_and_the_unvouched_road_is_unexported_chirho() {
    let crate_root_chirho = workspace_root_chirho().join(REGENESIS_CRATE_CHIRHO);
    let issuer_source_chirho =
        std::fs::read_to_string(crate_root_chirho.join("src/issuer_chirho.rs")).unwrap();
    let library_source_chirho =
        std::fs::read_to_string(crate_root_chirho.join("src/lib.rs")).unwrap();

    // Positive control: the two derivations still exist under the names this guard reasons about,
    // so a rename cannot turn every absence assertion below into a vacuous pass.
    for derivation_chirho in [
        "fn derived_kind_issuer_pin_chirho(",
        "fn derived_ledger_activation_pin_chirho(",
    ] {
        assert!(
            issuer_source_chirho.contains(derivation_chirho),
            "the guarded pin derivation is missing or renamed: {derivation_chirho}"
        );
    }

    for custody_bound_chirho in [
        "pub(crate) fn derived_kind_issuer_pin_chirho(",
        "pub(crate) fn derived_ledger_activation_pin_chirho(",
    ] {
        assert!(
            issuer_source_chirho.contains(custody_bound_chirho),
            "a pin derivation left the crate boundary; outside callers could then obtain a pin \
             without a custody proof: {custody_bound_chirho}"
        );
    }
    // Read each derivation's own PARAMETER LIST rather than counting occurrences file-wide: a raw
    // count would pass while the custody parameter sat on some neighbouring helper, and it would go
    // red for a harmless new helper — measuring the wrong thing in both directions.
    for derivation_chirho in [
        "pub(crate) fn derived_kind_issuer_pin_chirho(",
        "pub(crate) fn derived_ledger_activation_pin_chirho(",
    ] {
        let signature_start_chirho = issuer_source_chirho.find(derivation_chirho).unwrap();
        let signature_tail_chirho = &issuer_source_chirho[signature_start_chirho..];
        let signature_end_chirho = signature_tail_chirho.find(") -> ").unwrap();
        assert!(
            signature_tail_chirho[..signature_end_chirho]
                .contains("runtime_signers_chirho: &HostLedgerSignersChirho"),
            "a pin derivation stopped requiring the loaded runtime signers, so a pin could again be \
             produced with no custody proof: {derivation_chirho}"
        );
    }

    // Resolve the exported NAMES instead of grepping the file. A substring test cannot answer this
    // question at all: the custody-bound road is spelled `bind_custody_and_derive_ledger_host_
    // artifacts_chirho`, which CONTAINS the forbidden `derive_ledger_host_artifacts_chirho`, so a
    // text check is red whenever the closure is correct.
    let exported_names_chirho = public_use_leaf_names_chirho(&library_source_chirho);
    assert!(
        exported_names_chirho.contains("bind_custody_and_derive_ledger_host_artifacts_chirho"),
        "the custody-bound authoring road must stay exported (positive control for the name \
         resolution below — a parse that found nothing would make every absence assertion vacuous)"
    );
    for unvouched_export_chirho in [
        "derived_kind_issuer_pin_chirho",
        "derived_ledger_activation_pin_chirho",
        "derive_ledger_host_artifacts_chirho",
    ] {
        assert!(
            !exported_names_chirho.contains(unvouched_export_chirho),
            "the un-vouched derivation road was re-exported; the only exported authoring road must \
             be the custody-bound one: {unvouched_export_chirho}"
        );
    }
}

/// Every leaf name a `pub use` in this source re-exports, resolved through the use tree rather than
/// matched as text, so a longer name that merely CONTAINS a forbidden one cannot be mistaken for it.
fn public_use_leaf_names_chirho(source_chirho: &str) -> BTreeSet<String> {
    fn collect_chirho(tree_chirho: &syn::UseTree, names_chirho: &mut BTreeSet<String>) {
        match tree_chirho {
            syn::UseTree::Name(name_chirho) => {
                names_chirho.insert(name_chirho.ident.to_string());
            }
            syn::UseTree::Rename(rename_chirho) => {
                names_chirho.insert(rename_chirho.rename.to_string());
            }
            syn::UseTree::Path(path_chirho) => collect_chirho(&path_chirho.tree, names_chirho),
            syn::UseTree::Group(group_chirho) => {
                for item_chirho in &group_chirho.items {
                    collect_chirho(item_chirho, names_chirho);
                }
            }
            syn::UseTree::Glob(_) => {}
        }
    }
    let mut names_chirho = BTreeSet::new();
    for item_chirho in syn::parse_file(source_chirho).unwrap().items {
        if let syn::Item::Use(use_chirho) = item_chirho {
            if matches!(use_chirho.vis, syn::Visibility::Public(_)) {
                collect_chirho(&use_chirho.tree, &mut names_chirho);
            }
        }
    }
    names_chirho
}

/// Directory tripwire (completeness for the flat ambient/never-generate census above). That census
/// reads only TOP-LEVEL `src/*.rs`, so a future NESTED production module (`src/foo/bar.rs`) would
/// silently escape its `std::env::`/`OsRng`/create-road scan — a green-by-emptiness hole. Rather
/// than recurse, pin the crate's `src/` SHAPE: the only subdirectory is the all-test `tests_chirho/`.
/// A nested production module directory fails this loud and named, before the flat census can miss
/// its contents; reading directory ENTRIES (never file text) can never false-trip on a test-only
/// `std::env::`.
#[test]
fn regenesis_operator_src_subdirectories_are_exactly_the_all_test_dir_chirho() {
    let src_root_chirho = workspace_root_chirho()
        .join(REGENESIS_CRATE_CHIRHO)
        .join("src");
    let mut subdirectories_chirho: Vec<String> = std::fs::read_dir(&src_root_chirho)
        .unwrap()
        .map(|entry_chirho| entry_chirho.unwrap())
        .filter(|entry_chirho| entry_chirho.path().is_dir())
        .map(|entry_chirho| entry_chirho.file_name().to_string_lossy().into_owned())
        .collect();
    subdirectories_chirho.sort();
    // Exact set. A NEW subdirectory fails this the instant it appears; a MISSING tests_chirho would
    // fail it too — so the equality also proves the listing is real, never an empty vacuous scan.
    assert_eq!(
        subdirectories_chirho,
        vec!["tests_chirho".to_owned()],
        "regenesis operator src/ subdirectories changed. \
         regenesis_operator_source_has_no_ambient_or_generated_key_road_chirho scans only top-level \
         src/*.rs, so a nested production module here would silently escape that ambient/never-generate \
         census. Fold the module into a top-level src/*.rs file, or extend that census to recurse \
         BEFORE adding a src/ subdirectory."
    );
}

#[test]
fn completed_stage_publication_verifies_and_fsyncs_before_no_replace_rename_chirho() {
    let source_chirho = std::fs::read_to_string(
        workspace_root_chirho()
            .join(REGENESIS_CRATE_CHIRHO)
            .join("src/staging_chirho.rs"),
    )
    .unwrap();
    let function_start_chirho = source_chirho
        .find("pub fn publish_completed_stage_chirho(")
        .unwrap();
    let function_chirho = &source_chirho[function_start_chirho..];
    let recursive_fsync_chirho = function_chirho
        .find("bounded_recursive_fsync_chirho(&money_stage_chirho.staging_parent_chirho)?;")
        .unwrap();
    let resident_verify_chirho = function_chirho
        .find("verify_staged_resident_chirho(&money_stage_chirho)?;")
        .unwrap();
    let manifest_verify_chirho = function_chirho
        .find("verify_staged_publication_manifest_chirho(")
        .unwrap();
    let rename_chirho = function_chirho.find("no_replace_rename_chirho(").unwrap();
    let parent_fsync_chirho = function_chirho
        .find("fsync_dir_chirho(&selected_root_chirho)")
        .unwrap();
    assert!(recursive_fsync_chirho < rename_chirho);
    assert!(resident_verify_chirho < rename_chirho);
    assert!(manifest_verify_chirho < rename_chirho);
    assert!(rename_chirho < parent_fsync_chirho);
    assert!(
        !function_chirho[..parent_fsync_chirho].contains("fs::rename("),
        "publication must not regress to a destination-replacing rename"
    );
}

#[test]
fn h3b_zero_write_regression_pins_remain_in_the_flow_suites_chirho() {
    let root_chirho = workspace_root_chirho();
    let money_tests_chirho = std::fs::read_to_string(
        root_chirho
            .join(REGENESIS_CRATE_CHIRHO)
            .join("src/tests_chirho/money_stage_tests_chirho.rs"),
    )
    .unwrap();
    for test_name_chirho in [
        "bad_issuer_refuses_before_any_staging_or_final_write_chirho",
        "bad_initial_membership_refuses_before_any_staging_or_final_write_chirho",
    ] {
        assert!(
            money_tests_chirho.contains(test_name_chirho),
            "H3-B lost required F4 zero-write pin: {test_name_chirho}"
        );
    }

    let plan_tests_chirho = std::fs::read_to_string(
        root_chirho
            .join(REGENESIS_CRATE_CHIRHO)
            .join("src/tests_chirho/plan_tests_chirho.rs"),
    )
    .unwrap();
    for test_name_chirho in [
        "fresh_and_staging_parent_equality_refuses_without_any_namespace_write_chirho",
        "namespace_outside_fresh_parent_refuses_without_any_namespace_write_chirho",
    ] {
        assert!(
            plan_tests_chirho.contains(test_name_chirho),
            "H3-B lost required F5 namespace-layout pin: {test_name_chirho}"
        );
    }
}

#[test]
fn account_net_projection_reuses_the_reviewed_money_state_coding_chirho() {
    let root_chirho = workspace_root_chirho();
    let source_chirho = std::fs::read_to_string(
        root_chirho.join(
            "crates/ledger-chirho/cairn-ledger-read-model-chirho/src/feed_group_chirho/account_net_chirho.rs",
        ),
    )
    .unwrap();
    assert!(source_chirho.contains("VerifiedSourceStateChirho<'_>"));
    assert!(source_chirho.contains("AccountStateChirho {"));
    assert!(source_chirho.contains("state_chirho.net_money_chirho()"));
    for forbidden_chirho in [
        "credits_total_chirho as i128 -",
        "credits_chirho as i128 -",
        "debits_total_chirho as i128",
    ] {
        assert!(
            !source_chirho.contains(forbidden_chirho),
            "account-net projection gained a second money computation: {forbidden_chirho}"
        );
    }
}

#[test]
fn h3b_completion_orders_all_feeds_before_all_serves_and_packet_before_token_chirho() {
    let root_chirho = workspace_root_chirho();
    let source_chirho = std::fs::read_to_string(
        root_chirho
            .join(REGENESIS_CRATE_CHIRHO)
            .join("src/completion_chirho.rs"),
    )
    .unwrap();
    let build_start_chirho = source_chirho
        .find("fn build_evidence_packet_chirho(")
        .unwrap();
    let build_chirho = &source_chirho[build_start_chirho..];
    let feed_chirho = build_chirho.find(".feed_and_publish_chirho(").unwrap();
    let serve_chirho = build_chirho
        .find(".load_named_and_serve_with_view_chirho(")
        .unwrap();
    assert!(feed_chirho < serve_chirho);

    let complete_start_chirho = source_chirho
        .find("pub fn complete_money_stage_chirho(")
        .unwrap();
    let complete_chirho = &source_chirho[complete_start_chirho..build_start_chirho];
    let packet_write_chirho = complete_chirho
        .find("write_new_packet_durable_chirho(")
        .unwrap();
    let token_chirho = complete_chirho
        .find("Ok(CompletedLedgerRegenesisStageChirho {")
        .unwrap();
    assert!(packet_write_chirho < token_chirho);
}

#[test]
fn h3b_injectivity_and_completion_flow_pins_remain_permanent_chirho() {
    let root_chirho = workspace_root_chirho();
    let plan_tests_chirho = std::fs::read_to_string(
        root_chirho
            .join(REGENESIS_CRATE_CHIRHO)
            .join("src/tests_chirho/plan_tests_chirho.rs"),
    )
    .unwrap();
    for test_name_chirho in [
        "two_routes_sharing_one_head_refuse_without_any_namespace_write_chirho",
        "route_head_colliding_with_journal_refuses_without_any_namespace_write_chirho",
    ] {
        assert!(plan_tests_chirho.contains(test_name_chirho));
    }
    let completion_tests_chirho = std::fs::read_to_string(
        root_chirho
            .join(REGENESIS_CRATE_CHIRHO)
            .join("src/tests_chirho/completion_tests_chirho.rs"),
    )
    .unwrap();
    for test_name_chirho in [
        "all_routes_are_reserved_after_all_feeds_before_completion_chirho",
        "packet_is_reproducible_and_contains_no_host_or_key_coordinates_chirho",
        "publication_is_one_final_parent_with_the_packet_inside_ops_chirho",
    ] {
        assert!(completion_tests_chirho.contains(test_name_chirho));
    }
}

#[test]
fn h3_porcelain_has_one_create_call_and_no_caller_money_coordinates_chirho() {
    let root_chirho = workspace_root_chirho();
    let cli_source_chirho = std::fs::read_to_string(root_chirho.join(
        "crates/cairn-cli-chirho/src/cli_helpers_chirho/operations_chirho/ledger_regenesis_cli_chirho.rs",
    ))
    .unwrap();
    assert_eq!(
        cli_source_chirho
            .matches("run_ledger_regenesis_chirho(")
            .count(),
        1
    );
    let args_source_chirho = std::fs::read_to_string(
        root_chirho.join("crates/cairn-cli-chirho/src/args_chirho/core_chirho/ops_args_chirho.rs"),
    )
    .unwrap();
    let start_chirho = args_source_chirho
        .find("pub struct LedgerRegenesisArgsChirho")
        .unwrap();
    let tail_chirho = &args_source_chirho[start_chirho..];
    let end_chirho = tail_chirho.find("\n}\n").unwrap() + 3;
    let args_chirho = &tail_chirho[..end_chirho];
    for forbidden_chirho in [
        "amount_chirho",
        "journal_path_chirho",
        "storage_namespace_chirho",
    ] {
        assert!(!args_chirho.contains(forbidden_chirho));
    }
}

fn named_struct_fields_chirho(source_chirho: &str, struct_name_chirho: &str) -> Vec<String> {
    let syntax_chirho = syn::parse_file(source_chirho).unwrap();
    let struct_chirho = syntax_chirho
        .items
        .iter()
        .find_map(|item_chirho| match item_chirho {
            syn::Item::Struct(struct_chirho) if struct_chirho.ident == struct_name_chirho => {
                Some(struct_chirho)
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing reviewed wire struct {struct_name_chirho}"));
    let syn::Fields::Named(fields_chirho) = &struct_chirho.fields else {
        panic!("reviewed wire struct {struct_name_chirho} must keep named fields");
    };
    fields_chirho
        .named
        .iter()
        .map(|field_chirho| field_chirho.ident.as_ref().unwrap().to_string())
        .collect()
}

#[test]
fn compensation_authority_is_opaque_and_has_only_reviewed_production_callers_chirho() {
    let root_chirho = workspace_root_chirho();
    let cli_args_source_chirho = std::fs::read_to_string(
        root_chirho.join("crates/cairn-cli-chirho/src/args_chirho/core_chirho/ops_args_chirho.rs"),
    )
    .unwrap();
    assert_eq!(
        named_struct_fields_chirho(&cli_args_source_chirho, "LedgerCompensationArgsChirho"),
        [
            "config_path_chirho",
            "expected_config_digest_chirho",
            "app_chirho",
            "owner_chirho",
        ],
        "operator compensation porcelain gained caller-selected money or provider authority"
    );
    let authority_path_chirho = root_chirho.join(
        "src/execution_runtime_chirho/effect_chirho/postgres_reversible_chirho/compensation_authority_chirho.rs",
    );
    let authority_source_chirho = std::fs::read_to_string(&authority_path_chirho).unwrap();
    let authority_syntax_chirho = syn::parse_file(&authority_source_chirho).unwrap();
    let authority_struct_chirho = authority_syntax_chirho
        .items
        .iter()
        .find_map(|item_chirho| match item_chirho {
            syn::Item::Struct(struct_chirho)
                if struct_chirho.ident == "VerifiedCurrentUndoPlanAuthorityChirho" =>
            {
                Some(struct_chirho)
            }
            _ => None,
        })
        .expect("missing reviewed current-plan authority token");
    assert!(
        !authority_struct_chirho
            .attrs
            .iter()
            .any(|attribute_chirho| attribute_chirho.path().is_ident("derive")),
        "current-plan authority token must remain non-derivable"
    );
    let syn::Fields::Named(authority_fields_chirho) = &authority_struct_chirho.fields else {
        panic!("current-plan authority token must retain private named fields");
    };
    assert!(
        authority_fields_chirho
            .named
            .iter()
            .all(|field_chirho| matches!(field_chirho.vis, syn::Visibility::Inherited)),
        "current-plan authority token gained a public field"
    );
    for implementation_chirho in authority_syntax_chirho
        .items
        .iter()
        .filter_map(|item_chirho| match item_chirho {
            syn::Item::Impl(implementation_chirho) => Some(implementation_chirho),
            _ => None,
        })
    {
        let self_is_authority_chirho = match implementation_chirho.self_ty.as_ref() {
            syn::Type::Path(path_chirho) => {
                path_chirho
                    .path
                    .segments
                    .last()
                    .is_some_and(|segment_chirho| {
                        segment_chirho.ident == "VerifiedCurrentUndoPlanAuthorityChirho"
                    })
            }
            _ => false,
        };
        let forbidden_trait_chirho = implementation_chirho
            .trait_
            .as_ref()
            .and_then(|(_bang_chirho, path_chirho, _for_chirho)| {
                path_chirho
                    .segments
                    .last()
                    .map(|segment_chirho| segment_chirho.ident.to_string())
            })
            .is_some_and(|name_chirho| {
                ["Clone", "Debug", "Serialize", "Deserialize", "Default"]
                    .contains(&name_chirho.as_str())
            });
        assert!(
            !(self_is_authority_chirho && forbidden_trait_chirho),
            "current-plan authority token gained a manually implemented copy/display/wire/default road"
        );
    }
    let mut constructor_visitor_chirho = AuthorityConstructionVisitorChirho {
        current_function_chirho: None,
        constructors_chirho: BTreeSet::new(),
    };
    constructor_visitor_chirho.visit_file(&authority_syntax_chirho);
    assert_eq!(
        constructor_visitor_chirho.constructors_chirho,
        BTreeSet::from(["mint_verified_current_undo_plan_authority_chirho".to_owned()]),
        "current-plan authority token gained a second production constructor"
    );

    let mut calls_chirho = BTreeMap::new();
    let mut forbidden_indirections_chirho = Vec::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let source_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        let syntax_chirho = syn::parse_file(&source_chirho).unwrap_or_else(|error_chirho| {
            panic!(
                "parse {} for compensation caller guard: {error_chirho}",
                path_chirho.display()
            )
        });
        let relative_chirho = path_chirho
            .strip_prefix(&root_chirho)
            .unwrap_or(&path_chirho)
            .to_string_lossy()
            .to_string();
        CompensationCallerVisitorChirho {
            file_chirho: &relative_chirho,
            current_function_chirho: None,
            calls_chirho: &mut calls_chirho,
            forbidden_indirections_chirho: &mut forbidden_indirections_chirho,
        }
        .visit_file(&syntax_chirho);
    }
    assert!(
        forbidden_indirections_chirho.is_empty(),
        "compensation authority gained an indirect or renamed caller road: {forbidden_indirections_chirho:?}"
    );
    let expected_callers_chirho = BTreeMap::from([
        (
            "mint_verified_current_undo_plan_authority_chirho".to_owned(),
            BTreeSet::from([
                "crates/cairn-serve-runtime-chirho/src/serve_chirho/ledger_host_runtime_chirho/postgres_effect_chirho.rs::execute_current_compensation_chirho".to_owned(),
                "crates/cairn-serve-runtime-chirho/src/serve_chirho/ledger_host_runtime_chirho/postgres_effect_chirho.rs::preview_current_compensation_chirho".to_owned(),
                "src/execution_runtime_chirho/effect_chirho/postgres_reversible_chirho/compensation_authority_chirho.rs::preview_current_compensation_chirho".to_owned(),
            ]),
        ),
        (
            "preview_current_ledger_host_postgres_compensation_chirho".to_owned(),
            BTreeSet::from([
                "crates/cairn-cli-chirho/src/cli_helpers_chirho/operations_chirho/runtime_cli_chirho.rs::handle_runtime_command_chirho".to_owned(),
                "crates/ledger-chirho/cairn-ledger-geo-node-testkind-chirho/src/operator_control_chirho.rs::preview_chirho".to_owned(),
                "crates/services-chirho/cairn-operator-smoke-chirho/src/credits_demo_smoke_chirho/wire_smoke_chirho.rs::drive_compensation_chirho".to_owned(),
            ]),
        ),
        (
            "execute_current_ledger_host_postgres_compensation_chirho".to_owned(),
            BTreeSet::from([
                "crates/cairn-cli-chirho/src/cli_helpers_chirho/operations_chirho/runtime_cli_chirho.rs::handle_runtime_command_chirho".to_owned(),
                "crates/services-chirho/cairn-operator-smoke-chirho/src/credits_demo_smoke_chirho/wire_smoke_chirho.rs::drive_compensation_chirho".to_owned(),
            ]),
        ),
        (
            "execute_compensation_chirho".to_owned(),
            BTreeSet::from([
                "src/execution_runtime_chirho/effect_chirho/postgres_reversible_chirho/compensation_execution_chirho.rs::execute_current_compensation_chirho".to_owned(),
            ]),
        ),
    ]);
    assert_eq!(
        calls_chirho, expected_callers_chirho,
        "compensation authority caller set diverged from the reviewed operator-only cut"
    );

    let execution_source_chirho = std::fs::read_to_string(root_chirho.join(
        "src/execution_runtime_chirho/effect_chirho/postgres_reversible_chirho/compensation_execution_chirho.rs",
    ))
    .unwrap();
    let selection_start_chirho = execution_source_chirho
        .find("let run_chirho = if state_chirho")
        .expect("missing current compensation crash-selection branch");
    let selection_tail_chirho = &execution_source_chirho[selection_start_chirho..];
    let selection_end_chirho = selection_tail_chirho
        .find("let (terminal_outcome_ref_chirho, disposition_chirho)")
        .expect("missing current compensation terminal selection");
    let selection_chirho = &selection_tail_chirho[..selection_end_chirho];
    let else_chirho = selection_chirho
        .find("} else {")
        .expect("current compensation crash-selection branch lost its two postures");
    let recovery_chirho = &selection_chirho[..else_chirho];
    let fresh_chirho = &selection_chirho[else_chirho..];
    assert_eq!(
        recovery_chirho
            .matches(".reconcile_in_doubt_chirho(")
            .count(),
        1,
        "operator crash closure must use the targeted read-by-K reconcile door"
    );
    assert_eq!(
        recovery_chirho
            .matches(".execute_compensation_chirho(")
            .count(),
        0,
        "operator crash closure must not call the provider execute door again"
    );
    assert_eq!(
        fresh_chirho
            .matches(".execute_compensation_chirho(")
            .count(),
        1,
        "a fresh authorized compensation must use the one provider execute door"
    );
}

#[test]
fn cf7_credits_demo_has_only_inline_reviewed_read_and_spend_authority_chirho() {
    let root_chirho = workspace_root_chirho();
    let demo_root_chirho = root_chirho.join("examples-chirho/tree-credits-demo-chirho");
    let root_projection_wire_source_chirho = std::fs::read_to_string(
        root_chirho.join("src/execution_runtime_chirho/effect_chirho/projection_read_chirho.rs"),
    )
    .unwrap();
    let descriptor_chirho =
        std::fs::read_to_string(demo_root_chirho.join("app-chirho.toml")).unwrap();
    assert!(!descriptor_chirho.contains("internal_module_chirho"));
    assert!(!descriptor_chirho.contains("preview_undo_chirho"));
    assert!(descriptor_chirho.contains("dag_chirho = \"view_balance_chirho\""));
    assert!(descriptor_chirho.contains("dag_chirho = \"spend_credits_chirho\""));

    for removed_path_chirho in [
        "dags_chirho/apply_spend_chirho",
        "dags_chirho/preview_undo_chirho",
        "src/implementations_chirho/render_undo_preview_chirho.rs",
        "src/types_chirho/undo_preview_v1_chirho.rs",
    ] {
        assert!(
            !demo_root_chirho.join(removed_path_chirho).exists(),
            "CF7 public placeholder authority returned at {removed_path_chirho}"
        );
    }

    let form_source_chirho =
        std::fs::read_to_string(demo_root_chirho.join("src/types_chirho/form_post_v1_chirho.rs"))
            .unwrap();
    let request_source_chirho = std::fs::read_to_string(
        demo_root_chirho.join("src/types_chirho/reversible_postgres_request_v1_chirho.rs"),
    )
    .unwrap();
    let projection_wire_source_chirho = std::fs::read_to_string(
        demo_root_chirho.join("src/types_chirho/published_projection_read_chirho.rs"),
    )
    .unwrap();
    assert_eq!(
        named_struct_fields_chirho(&form_source_chirho, "FormPostV1Chirho"),
        ["item_chirho", "concurrency_token_chirho"],
        "CF7 form wire gained authority outside the reviewed item/token pair"
    );
    assert_eq!(
        named_struct_fields_chirho(&request_source_chirho, "ReversiblePostgresRequestV1Chirho",),
        [
            "schema_chirho",
            "subject_chirho",
            "row_key_chirho",
            "expected_before_chirho",
            "desired_chirho",
        ],
        "CF7 reversible request wire diverged from its reviewed fixed-coordinate shape"
    );
    assert_eq!(
        named_struct_fields_chirho(
            &projection_wire_source_chirho,
            "PublishedProjectionReadResponseV2Chirho",
        ),
        [
            "schema_chirho",
            "viewer_principal_chirho",
            "cost_class_chirho",
            "outcome_chirho",
            "view_chirho",
        ],
        "CF7 projection response lost its runtime-derived viewer binding"
    );
    assert_eq!(
        named_struct_fields_chirho(
            &root_projection_wire_source_chirho,
            "PublishedProjectionReadResponseChirho",
        ),
        [
            "schema_chirho",
            "viewer_principal_chirho",
            "cost_class_chirho",
            "outcome_chirho",
            "view_chirho",
        ],
        "root projection response diverged from the reviewed viewer-bound v2 envelope"
    );
    assert!(!projection_wire_source_chirho.contains("BALANCE_ACCOUNT_OWNER_CHIRHO"));
    assert!(!projection_wire_source_chirho.contains("verified-credits-user-chirho"));
    let balance_html_chirho = std::fs::read_to_string(
        demo_root_chirho
            .join("fixtures_chirho/node-expected-chirho/render_balance_fresh_output_chirho.html"),
    )
    .unwrap();
    for forbidden_chirho in ["amount_text_chirho", "amount_credits_chirho"] {
        assert!(!form_source_chirho.contains(forbidden_chirho));
        assert!(!request_source_chirho.contains(forbidden_chirho));
        assert!(!balance_html_chirho.contains(forbidden_chirho));
    }
    assert!(!balance_html_chirho.contains("name=\"amount"));
    assert!(balance_html_chirho.contains("name=\"item_chirho\""));
    assert!(balance_html_chirho.contains("name=\"concurrency_token_chirho\""));

    let query_card_chirho = std::fs::read_to_string(demo_root_chirho.join(
        "dags_chirho/view_balance_chirho/nodes_chirho/query_balance_chirho/blessed-contract-chirho.toml",
    ))
    .unwrap();
    assert!(query_card_chirho.contains("contract_chirho = \"query\""));
    assert!(query_card_chirho.contains("max_rows_chirho = 1"));
    assert!(query_card_chirho.contains("caller_chirho = \"credits-demo-spend-role-chirho\""));
    assert!(!query_card_chirho.contains("verified-credits-user-chirho"));
    let spend_card_chirho = std::fs::read_to_string(demo_root_chirho.join(
        "dags_chirho/spend_credits_chirho/nodes_chirho/commit_spend_chirho/blessed-contract-chirho.toml",
    ))
    .unwrap();
    assert!(spend_card_chirho.contains("contract_chirho = \"postgres-reversible\""));
    assert!(spend_card_chirho.contains("caller_chirho = \"credits-demo-spend-role-chirho\""));
    assert!(!spend_card_chirho.contains("verified-credits-user-chirho"));
}

#[test]
fn cf7_local_phase_b_effect_lane_keeps_one_injected_authority_shape_chirho() {
    let root_chirho = workspace_root_chirho();
    let config_source_chirho = std::fs::read_to_string(
        root_chirho.join("crates/support-chirho/cairn-config-chirho/src/config_chirho.rs"),
    )
    .unwrap();
    assert_eq!(
        named_struct_fields_chirho(
            &config_source_chirho,
            "LedgerHostPostgresEffectConfigChirho",
        ),
        [
            "schema_chirho",
            "posture_chirho",
            "connection_secret_chirho",
            "billing_kind_chirho",
        ],
        "LocalPhaseB config gained caller-selected provider, payer, price, amount, or route authority"
    );
    let config_syntax_chirho = syn::parse_file(&config_source_chirho).unwrap();
    let posture_variants_chirho = config_syntax_chirho
        .items
        .iter()
        .find_map(|item_chirho| match item_chirho {
            syn::Item::Enum(enum_chirho)
                if enum_chirho.ident == "LedgerHostPostgresEffectPostureChirho" =>
            {
                Some(
                    enum_chirho
                        .variants
                        .iter()
                        .map(|variant_chirho| variant_chirho.ident.to_string())
                        .collect::<Vec<_>>(),
                )
            }
            _ => None,
        })
        .expect("missing LocalPhaseB posture enum");
    assert_eq!(posture_variants_chirho, ["LocalPhaseBChirho"]);

    let adapter_source_chirho = std::fs::read_to_string(root_chirho.join(
        "crates/cairn-serve-runtime-chirho/src/serve_chirho/ledger_host_runtime_chirho/postgres_effect_chirho.rs",
    ))
    .unwrap();
    for forbidden_chirho in ["std::env::", "set_secret_chirho(", "thread_local!"] {
        assert!(
            !adapter_source_chirho.contains(forbidden_chirho),
            "LocalPhaseB adapter gained ambient authority: {forbidden_chirho}"
        );
    }
    assert!(
        adapter_source_chirho.contains("Arc<Mutex<Box<dyn LedgerHostPostgresEffectPortChirho>>>")
    );
    assert!(!adapter_source_chirho.contains("install_reversible_postgres_schema_chirho"));
    assert!(!adapter_source_chirho.contains("Client::connect"));
    assert!(adapter_source_chirho.contains("parse_local_phase_b_connection_config_chirho("));
    assert!(adapter_source_chirho.contains("ConnectionOutsideLocalPhaseBChirho"));
    assert!(
        adapter_source_chirho.contains("journal_chirho: ResidentEffectJournalHandleChirho")
            && adapter_source_chirho.contains("open_resident_effect_journal_handle_chirho("),
        "served Descriptor-D mutations must retain the process-resident elected journal handle"
    );
    for forbidden_chirho in ["LedgerWriteCompositionChirho", ".open_journal_chirho("] {
        assert!(
            !adapter_source_chirho.contains(forbidden_chirho),
            "served Descriptor-D mutations must not reopen raw write authority: {forbidden_chirho}"
        );
    }
    let prepare_start_chirho = adapter_source_chirho
        .find("fn prepare_ledger_host_postgres_effect_runtime_chirho(")
        .unwrap();
    let prepare_end_chirho = adapter_source_chirho[prepare_start_chirho..]
        .find("fn shared_ledger_host_postgres_effect_runtime_from_parts_chirho(")
        .map(|offset_chirho| prepare_start_chirho + offset_chirho)
        .unwrap();
    let prepare_chirho = &adapter_source_chirho[prepare_start_chirho..prepare_end_chirho];
    let route_preflight_chirho = prepare_chirho
        .find("current_feed_routes_for_host_chirho(host_chirho)?;")
        .unwrap();
    let billing_preflight_chirho = prepare_chirho
        .find("verify_current_billing_kind_for_host_chirho(")
        .unwrap();
    let connect_chirho = prepare_chirho
        .find("connect_local_phase_b_database_chirho(")
        .unwrap();
    assert!(route_preflight_chirho < connect_chirho);
    assert!(billing_preflight_chirho < connect_chirho);
    let shared_open_start_chirho = adapter_source_chirho
        .find(
            "pub fn open_shared_ledger_host_postgres_effect_runtime_with_resident_journal_chirho(",
        )
        .unwrap();
    let shared_open_chirho = &adapter_source_chirho[shared_open_start_chirho..prepare_start_chirho];
    assert!(
        shared_open_chirho
            .find("verify_runtime_binding_chirho(")
            .unwrap()
            < shared_open_chirho
                .find("prepare_ledger_host_postgres_effect_runtime_chirho(")
                .unwrap(),
        "an injected resident actor must bind the exact root/config before provider preflight"
    );

    let execute_start_chirho = adapter_source_chirho
        .find("impl PostgresReversibleRuntimePortChirho")
        .unwrap();
    let execute_chirho = &adapter_source_chirho[execute_start_chirho..];
    let terminal_parse_chirho = execute_chirho
        .find("parse_canonical_postgres_effect_terminal_disposition_chirho(")
        .unwrap();
    let refeed_call_chirho = execute_chirho
        .find("refeed_committed_terminal_chirho(&disposition_chirho")
        .unwrap();
    assert!(terminal_parse_chirho < refeed_call_chirho);

    let refeed_start_chirho = adapter_source_chirho
        .find("fn refeed_committed_terminal_chirho(")
        .unwrap();
    let refeed_chirho = &adapter_source_chirho[refeed_start_chirho..execute_start_chirho];
    let committed_gate_chirho = refeed_chirho
        .find("EffectTerminalDispositionChirho::CommittedChirho")
        .unwrap();
    let feed_chirho = refeed_chirho.find("feed_chirho().err()").unwrap();
    assert!(committed_gate_chirho < feed_chirho);

    let runtime_source_chirho = std::fs::read_to_string(
        root_chirho
            .join("crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_ports_chirho.rs"),
    )
    .unwrap();
    assert!(runtime_source_chirho.contains("run_dag_with_intent_and_effect_runtime_chirho("));
    assert!(runtime_source_chirho
        .contains("run_dag_with_private_input_intent_and_effect_runtime_chirho("));
    assert_eq!(
        runtime_source_chirho
            .matches("with_runtime_chirho(")
            .count(),
        3,
        "startup Resume plus served public and private paths must share the one provider mutex"
    );
    // Served-overload (ii): startup Resume enters the typed boundary directly; the two served paths enter it through
    // `spawn_blocking_served_run_chirho`, which runs EVERY served run on the blocking pool and sends a Postgres
    // configuration through the same typed boundary. So all three provider-mutex sections still execute behind it.
    assert_eq!(
        runtime_source_chirho
            .matches("spawn_blocking_provider_task_chirho(move ||")
            .count(),
        1,
        "startup Resume must execute behind the one typed blocking boundary"
    );
    assert_eq!(
        runtime_source_chirho
            .matches("spawn_blocking_served_run_chirho(self.postgres_effect_chirho.is_some(), move ||")
            .count(),
        2,
        "the served public and private provider-mutex sections must execute behind the served blocking boundary"
    );
    let served_boundary_start_chirho = runtime_source_chirho
        .find("async fn spawn_blocking_served_run_chirho<")
        .unwrap();
    let served_boundary_chirho = &runtime_source_chirho[served_boundary_start_chirho..];
    let served_boundary_chirho =
        &served_boundary_chirho[..served_boundary_chirho.find("\n}\n").unwrap()];
    assert!(
        served_boundary_chirho
            .find("if postgres_configured_chirho {")
            .unwrap()
            < served_boundary_chirho
                .find("return spawn_blocking_provider_task_chirho(task_chirho).await;")
                .unwrap(),
        "a Postgres configuration's served run must keep the one typed blocking boundary"
    );
    let serve_source_chirho = [
        "crates/cairn-serve-runtime-chirho/src/serve_chirho.rs",
        "crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_lifecycle_chirho/startup_chirho.rs",
    ]
    .map(|path_chirho| std::fs::read_to_string(root_chirho.join(path_chirho)).unwrap())
    .join("\n");
    assert!(serve_source_chirho.contains("if postgres_effect_chirho.is_some()"));
    assert!(serve_source_chirho.contains("effect_host_projection_read_port_chirho("));
    assert!(serve_source_chirho
        .contains("resume_unfinished_run_intents_for_served_effect_runtime_chirho("));
    assert_eq!(
        serve_source_chirho.matches("with_runtime_chirho(").count(),
        0,
        "async serve startup must not acquire the synchronous provider mutex on its worker"
    );
    let host_runtime_source_chirho =
        std::fs::read_to_string(root_chirho.join(
            "crates/cairn-serve-runtime-chirho/src/serve_chirho/ledger_host_runtime_chirho.rs",
        ))
        .unwrap();
    assert_eq!(
        named_struct_fields_chirho(
            &host_runtime_source_chirho,
            "EffectHostExactCutProjectionReadPortChirho",
        ),
        ["host_chirho"],
        "the effect-host exact-cut adapter gained a second read authority"
    );
    assert!(host_runtime_source_chirho.contains("load_named_and_serve_with_view_exact_cut_chirho("));

    let read_model_source_chirho = std::fs::read_to_string(root_chirho.join(
        "crates/ledger-chirho/cairn-ledger-read-model-chirho/src/serve_group_chirho/serving_chirho.rs",
    ))
    .unwrap();
    assert!(read_model_source_chirho.contains("EffectCutBehindChirho"));
    assert!(read_model_source_chirho.contains("view_prefix_chirho.source_seq_chirho"));
    assert!(read_model_source_chirho.contains("view_prefix_chirho.signed_prefix_digest_chirho"));
    assert!(read_model_source_chirho.contains("view_prefix_chirho.source_hlc_chirho"));
    let cli_source_chirho = std::fs::read_to_string(root_chirho.join(
        "crates/cairn-cli-chirho/src/cli_helpers_chirho/operations_chirho/runtime_cli_chirho.rs",
    ))
    .unwrap();
    assert_eq!(
        cli_source_chirho
            .matches("open_shared_ledger_host_postgres_effect_runtime_chirho(")
            .count(),
        2,
        "only configured up and operator compensation may construct the LocalPhaseB provider"
    );
}
