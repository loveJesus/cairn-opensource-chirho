// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Structural guard for the native tenant-placement population verifier.
//!
//! This is deliberately a source/dependency census, not behavioral proof that any signed placement
//! is correct. It keeps authoring, file-output, election, and migration operations out of the
//! verifier's callable source boundary. `cairn-signer-chirho` reaches `cairn-durable-chirho`
//! transitively, so this guard does not claim the entire linked dependency graph is read-only;
//! signature behavior and projection bindings remain owned by causal tests in the authority crate.

use super::workspace_root_chirho;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use syn::visit::Visit;

const VERIFIER_PACKAGE_CHIRHO: &str = "cairn-tenant-placement-authority-chirho";
const VERIFIER_BINARY_RELATIVE_CHIRHO: &str = "crates/stores-chirho/\
cairn-tenant-placement-authority-chirho/src/bin/cairn-tenant-placement-verify-chirho.rs";
const VERIFIER_PROJECTION_RELATIVE_CHIRHO: &str = "crates/stores-chirho/\
cairn-tenant-placement-authority-chirho/src/population_projection_chirho.rs";
const VERIFIER_AUTHORITY_RELATIVE_CHIRHO: &str =
    "crates/stores-chirho/cairn-tenant-placement-authority-chirho/src/lib.rs";
const CAPACITY_ADMISSION_ADAPTER_RELATIVE_CHIRHO: &str = "crates/stores-chirho/\
cairn-tenant-placement-authority-chirho/src/capacity_admission_impl_chirho.rs";
const PLACEMENT_REGISTRY_LOADER_RELATIVE_CHIRHO: &str = "crates/stores-chirho/\
cairn-tenant-placement-authority-chirho/src/placement_registry_load_chirho.rs";

#[derive(Default)]
struct VerifierIdentifierCensusChirho {
    names_chirho: BTreeSet<String>,
    argument_reads_chirho: usize,
}

impl<'ast_chirho> Visit<'ast_chirho> for VerifierIdentifierCensusChirho {
    fn visit_path(&mut self, path_chirho: &'ast_chirho syn::Path) {
        for segment_chirho in &path_chirho.segments {
            self.names_chirho.insert(segment_chirho.ident.to_string());
        }
        syn::visit::visit_path(self, path_chirho);
    }

    fn visit_expr_call(&mut self, call_chirho: &'ast_chirho syn::ExprCall) {
        if let syn::Expr::Path(path_chirho) = call_chirho.func.as_ref() {
            if path_chirho
                .path
                .segments
                .last()
                .is_some_and(|segment_chirho| segment_chirho.ident == "next_utf8_chirho")
            {
                self.argument_reads_chirho += 1;
            }
        }
        syn::visit::visit_expr_call(self, call_chirho);
    }

    fn visit_expr_method_call(&mut self, call_chirho: &'ast_chirho syn::ExprMethodCall) {
        self.names_chirho.insert(call_chirho.method.to_string());
        syn::visit::visit_expr_method_call(self, call_chirho);
    }

    // Formatting macros write only to an already-provided formatter/stdout handle. File-output
    // authority is censused through callable paths and methods (`fs::write`, `create`,
    // `OpenOptions`, `write_all`) instead of conflating `fmt::write!` with filesystem mutation.
    fn visit_macro(&mut self, _macro_chirho: &'ast_chirho syn::Macro) {}
}

fn dependency_graph_chirho() -> BTreeMap<String, BTreeSet<String>> {
    let lock_chirho = std::fs::read_to_string(workspace_root_chirho().join("Cargo.lock"))
        .expect("read Cargo.lock for verifier dependency closure");
    let parsed_chirho = lock_chirho
        .parse::<toml::Value>()
        .expect("parse Cargo.lock for verifier dependency closure");
    let mut graph_chirho = BTreeMap::<String, BTreeSet<String>>::new();
    for package_chirho in parsed_chirho
        .get("package")
        .and_then(toml::Value::as_array)
        .expect("Cargo.lock package population")
    {
        let name_chirho = package_chirho
            .get("name")
            .and_then(toml::Value::as_str)
            .expect("locked package name")
            .to_string();
        let dependencies_chirho = graph_chirho.entry(name_chirho).or_default();
        if let Some(entries_chirho) = package_chirho
            .get("dependencies")
            .and_then(toml::Value::as_array)
        {
            for entry_chirho in entries_chirho {
                let dependency_chirho = entry_chirho
                    .as_str()
                    .expect("locked dependency coordinate")
                    .split_whitespace()
                    .next()
                    .expect("locked dependency name");
                dependencies_chirho.insert(dependency_chirho.to_string());
            }
        }
    }
    graph_chirho
}

fn reachable_dependencies_chirho(
    graph_chirho: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeSet<String> {
    let mut reachable_chirho = BTreeSet::new();
    let mut pending_chirho = VecDeque::from([VERIFIER_PACKAGE_CHIRHO.to_string()]);
    while let Some(package_chirho) = pending_chirho.pop_front() {
        if !reachable_chirho.insert(package_chirho.clone()) {
            continue;
        }
        if let Some(dependencies_chirho) = graph_chirho.get(&package_chirho) {
            pending_chirho.extend(dependencies_chirho.iter().cloned());
        }
    }
    reachable_chirho
}

fn function_identifier_census_chirho(
    source_chirho: &str,
    function_name_chirho: &str,
) -> VerifierIdentifierCensusChirho {
    let syntax_chirho = syn::parse_file(source_chirho).expect("parse guarded Rust source");
    let function_chirho = syntax_chirho
        .items
        .iter()
        .find_map(|item_chirho| match item_chirho {
            syn::Item::Fn(function_chirho) if function_chirho.sig.ident == function_name_chirho => {
                Some(function_chirho)
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing guarded function {function_name_chirho}"));
    let mut census_chirho = VerifierIdentifierCensusChirho::default();
    census_chirho.visit_item_fn(function_chirho);
    census_chirho
}

#[test]
fn tenant_placement_population_verifier_has_no_authoring_or_file_write_authority_chirho() {
    let root_chirho = workspace_root_chirho();
    let binary_source_chirho =
        std::fs::read_to_string(root_chirho.join(VERIFIER_BINARY_RELATIVE_CHIRHO))
            .expect("read tenant-placement verifier binary");
    let projection_source_chirho =
        std::fs::read_to_string(root_chirho.join(VERIFIER_PROJECTION_RELATIVE_CHIRHO))
            .expect("read tenant-placement verifier projection");
    let authority_source_chirho =
        std::fs::read_to_string(root_chirho.join(VERIFIER_AUTHORITY_RELATIVE_CHIRHO))
            .expect("read tenant-placement authority verifier");
    let mut census_chirho = VerifierIdentifierCensusChirho::default();
    for (label_chirho, source_chirho) in [
        ("binary", binary_source_chirho.as_str()),
        ("projection", projection_source_chirho.as_str()),
        ("authority", authority_source_chirho.as_str()),
    ] {
        let syntax_chirho = syn::parse_file(source_chirho)
            .unwrap_or_else(|error_chirho| panic!("parse {label_chirho}: {error_chirho}"));
        census_chirho.visit_file(&syntax_chirho);
    }

    assert_eq!(
        census_chirho.argument_reads_chirho, 4,
        "the verifier grammar must stay exactly record path plus three public-key values; no output, sign-root, node, role, or authority argument may appear"
    );
    for required_chirho in [
        "record_path_chirho",
        "expected_placement_key_chirho",
        "roster_operator_key_chirho",
        "geo_plan_authority_key_chirho",
    ] {
        assert!(
            binary_source_chirho.contains(required_chirho),
            "verifier grammar lost required bounded input {required_chirho}"
        );
    }
    for forbidden_argument_chirho in [
        "output_path_chirho",
        "sign_root_chirho",
        "private_key_chirho",
        "tenant_id_chirho",
        "node_id_chirho",
        "role_chirho",
    ] {
        assert!(
            !binary_source_chirho.contains(forbidden_argument_chirho),
            "verifier grammar gained forbidden caller authority {forbidden_argument_chirho}"
        );
    }

    for forbidden_identifier_chirho in [
        "OpenOptions",
        "create",
        "write",
        "write_all",
        "write_fmt",
        "rename",
        "remove_file",
        "author_tenant_placement_record_chirho",
        "write_new_json_chirho",
        "sign_message_chirho",
        "sign_with_existing_key_possession_chirho",
        "append",
        "mint",
        "elect",
        "refresh_lease",
        "commit_adoption",
    ] {
        assert!(
            !census_chirho.names_chirho.contains(forbidden_identifier_chirho),
            "tenant-placement verifier reached forbidden authoring/write identifier {forbidden_identifier_chirho}"
        );
    }

    let graph_chirho = dependency_graph_chirho();
    let reachable_chirho = reachable_dependencies_chirho(&graph_chirho);
    assert!(
        reachable_chirho.contains("cairn-signer-chirho"),
        "dependency census lost the signer verifier positive control"
    );
    for forbidden_package_chirho in [
        "cairn-tenant-placement-author-chirho",
        "cairn-writer-elector-http-chirho",
        "cairn-ledger-tenant-migration-chirho",
    ] {
        assert!(
            !reachable_chirho.contains(forbidden_package_chirho),
            "tenant-placement verifier dependency closure reached forbidden package {forbidden_package_chirho}"
        );
    }
}

#[test]
fn capacity_admission_reaches_only_the_strict_usage_reader_chirho() {
    let root_chirho = workspace_root_chirho();
    let adapter_source_chirho =
        std::fs::read_to_string(root_chirho.join(CAPACITY_ADMISSION_ADAPTER_RELATIVE_CHIRHO))
            .expect("read production capacity admission adapter");
    let loader_source_chirho =
        std::fs::read_to_string(root_chirho.join(PLACEMENT_REGISTRY_LOADER_RELATIVE_CHIRHO))
            .expect("read placement registry loader");

    let adapter_syntax_chirho =
        syn::parse_file(&adapter_source_chirho).expect("parse capacity admission adapter");
    let mut adapter_census_chirho = VerifierIdentifierCensusChirho::default();
    adapter_census_chirho.visit_file(&adapter_syntax_chirho);
    assert!(
        adapter_census_chirho
            .names_chirho
            .contains("load_verified_placement_registry_for_admission_chirho"),
        "positive control: the production adapter must call the strict registry loader"
    );
    assert!(
        !adapter_census_chirho
            .names_chirho
            .contains("load_verified_placement_registry_chirho"),
        "the production admission module must not name the permissive registry loader"
    );

    let ordinary_loader_chirho = function_identifier_census_chirho(
        &loader_source_chirho,
        "load_verified_placement_registry_chirho",
    );
    assert!(
        ordinary_loader_chirho
            .names_chirho
            .contains("verified_measurements_in_order_chirho"),
        "positive control: the ordinary report loader must retain its permissive reader"
    );
    assert!(
        !ordinary_loader_chirho
            .names_chirho
            .contains("verified_measurements_in_order_for_admission_chirho"),
        "the ordinary loader and strict admission loader must remain distinct"
    );

    let admission_loader_chirho = function_identifier_census_chirho(
        &loader_source_chirho,
        "load_verified_placement_registry_for_admission_chirho",
    );
    assert!(
        admission_loader_chirho
            .names_chirho
            .contains("verified_measurements_in_order_for_admission_chirho"),
        "the authority-bearing admission loader must select the strict usage reader"
    );
    assert!(
        !admission_loader_chirho
            .names_chirho
            .contains("verified_measurements_in_order_chirho"),
        "the admission loader must not retain a permissive usage-reader path"
    );
}
