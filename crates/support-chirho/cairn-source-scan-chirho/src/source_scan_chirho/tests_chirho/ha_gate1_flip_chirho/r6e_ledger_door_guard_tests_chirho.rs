// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::super::*;
use std::collections::{BTreeMap, BTreeSet};
use syn::visit::Visit;

type PostingTypeCoordinateChirho = (String, String, String, String);
type PostingCallEdgeChirho = (String, String, String);

const POSTING_FAMILY_CHIRHO: &[&str] = &[
    "post_entry_chirho",
    "post_entry_tagged_chirho",
    "post_entry_tagged_checked_chirho",
    "post_entry_once_tagged_checked_chirho",
    "post_entry_tagged_checked_unlocked_chirho",
    "post_entry_once_tagged_checked_unlocked_chirho",
    "transfer_chirho",
    "transfer_checked_chirho",
    "transfer_tagged_chirho",
    "transfer_tagged_checked_chirho",
    "charge_gas_chirho",
];

// Roles are review evidence. The assertion compares the coordinate keys, never only their count.
// FOUR ROWS REPATHED 2026-07-25 by CF6-D2 brick (a2-0): assert_balanced_chirho, entry_message_chirho,
// entry_signature_message_chirho and V2EntryMessageChirho moved to the retained legacy-ledger
// evidence module so authenticating historical ledger evidence survives the spine's deletion.
// THE DIFF IS THE EVIDENCE THE MOVE WAS A RELOCATION: same item, same role, same field, only the
// path changed -- nothing entered this census and nothing left it. An extraction that had rewritten
// a signature or dropped a validator would have shown up here as an added or missing coordinate.
//
// THE SAME INSTRUMENT ANSWERED THE SAME QUESTION AGAIN AT CF6 WAVE-1 (2026-07-26): TWENTY -> THIRTEEN,
// and the shape of the diff is the finding. SEVEN genuine deaths, all `economic_flows_chirho/
// ledger_chirho.rs` substrate primitives plus `LedgerAppendInputChirho`, gone with the money spine.
// ONE RELOCATION: `assert_ledger_entry_chirho` moved from `execution_runtime_chirho/realtime_chirho.rs`
// to the retained `privacy_compliance_chirho/realtime_ledger_bound_evidence_chirho.rs` with owner,
// kind and slot BYTE-IDENTICAL -- only the path differs. ZERO additions.
//
// That matters beyond bookkeeping: the wave-1 spec argued the realtime verifiers were a MOVE rather
// than a rewrite, with every symbol resolving to a kept home. This census was built for a different
// brick and had no stake in that argument, and it independently produced the relocation signature the
// claim predicted. A rewrite would have shown an added coordinate or a lost validator here.
const EXPECTED_POSTING_TYPE_COORDINATES_CHIRHO: &[(&str, &str, &str, &str, &str)] = &[
    // CF6-D2 brick (a2-0)'s acceptance instrument. Builds fixture postings for a temp-dir corpus it
    // then deletes; it reaches no write door at all -- R6e retired the unchecked one, so the
    // instrument hand-builds its entry and proves the signature format from the READ side instead.
    // Counted here only because `cfg(all(test, feature = ...))` reads as ambiguous to the scanner,
    // which fails safe into the production surface. Leaves with brick (a2).
    (
        "src/legacy_evidence_chirho/legacy_ledger_characterization_tests_chirho.rs",
        "postings_chirho",
        "return",
        "return_chirho",
        "test-fixture-constructor",
    ),
    // CF6-D2 brick (a2-2)'s acceptance instrument, admitted on the same ground as the (a2-0) row
    // above: it hand-builds fixture postings for a temp-dir corpus it then deletes, and reaches no
    // write door -- R6e retired the unchecked one, and the checked one refuses a debit against an
    // empty account, so neither could seed a corpus. The keystone arm recovers what a write-side
    // fixture would have shown by proving production ACCEPTS entries this file signed itself.
    // Counted only because the ambiguous cfg fails safe into the production surface. Leaves with (a2).
    (
        "src/legacy_evidence_chirho/legacy_holds_characterization_tests_chirho.rs",
        "entry_chirho",
        "input",
        "postings_chirho",
        "test-fixture-constructor",
    ),
    (
        "src/legacy_evidence_chirho/legacy_holds_characterization_tests_chirho.rs",
        "posting_chirho",
        "return",
        "return_chirho",
        "test-fixture-constructor",
    ),
    // CF6-D2 brick (a2-3): the billing acceptance instrument's three PostingChirho-bearing fixture
    // constructors. Same role and same admission reason as the holds instrument's two above --
    // test-fixture constructors in a #[cfg(test)] module the scanner counts as production because
    // `cfg(all(test, feature = ...))` reads as ambiguous and FAILS SAFE. `cash_posting_chirho` exists
    // because the Token-only helper made the ASSET conjunct of both billing posting predicates
    // unpinnable by construction; it builds Cash legs so an arm can violate the binding while the
    // entry still conserves. None of the three is a door: they construct values a fixture then
    // signs, and no production caller can reach them. All three leave with brick (a2).
    (
        "src/legacy_evidence_chirho/legacy_billing_characterization_tests_chirho.rs",
        "cash_posting_chirho",
        "return",
        "return_chirho",
        "test-fixture-constructor",
    ),
    (
        "src/legacy_evidence_chirho/legacy_billing_characterization_tests_chirho.rs",
        "entry_chirho",
        "input",
        "postings_chirho",
        "test-fixture-constructor",
    ),
    (
        "src/legacy_evidence_chirho/legacy_billing_characterization_tests_chirho.rs",
        "posting_chirho",
        "return",
        "return_chirho",
        "test-fixture-constructor",
    ),
    (
        "crates/domain-chirho/cairn-model-economic-chirho/src/billing_postings_chirho.rs",
        "compensation_postings_for_usage_chirho",
        "return",
        "return_chirho",
        "builder-return",
    ),
    (
        "crates/domain-chirho/cairn-model-economic-chirho/src/ledger_chirho.rs",
        "LedgerEntryChirho",
        "field",
        "postings_chirho",
        "data-field",
    ),
    (
        "src/legacy_evidence_chirho/legacy_ledger_evidence_chirho.rs",
        "V2EntryMessageChirho",
        "field",
        "postings_chirho",
        "signature-data",
    ),
    (
        "src/legacy_evidence_chirho/legacy_ledger_evidence_chirho.rs",
        "assert_balanced_chirho",
        "input",
        "postings_chirho",
        "validator",
    ),
    (
        "src/legacy_evidence_chirho/legacy_ledger_evidence_chirho.rs",
        "entry_message_chirho",
        "input",
        "postings_chirho",
        "signature-message",
    ),
    (
        "src/legacy_evidence_chirho/legacy_ledger_evidence_chirho.rs",
        "entry_signature_message_chirho",
        "input",
        "postings_chirho",
        "signature-message",
    ),
    (
        "src/privacy_compliance_chirho/realtime_ledger_bound_evidence_chirho.rs",
        "assert_ledger_entry_chirho",
        "input",
        "postings_chirho",
        "private-verifier",
    ),
];

// The classification note that stood here ("every external edge is derived-not-passed, billing
// refund is the named backing exception") described the frozen call-edge manifest, and went dormant
// with it at CF6 wave-1 -- it classified rows that no longer exist. Recover both together from
// archive-chirho/26-07-26-cf6-wave1-money-spine-chirho when the V2 door gets its own manifest; the
// derived-not-passed rule is the thing worth carrying forward, not the row list.

struct ProductionSyntaxChirho {
    file_chirho: String,
    syntax_chirho: syn::File,
}

fn production_syntaxes_containing_chirho(needles_chirho: &[&str]) -> Vec<ProductionSyntaxChirho> {
    let root_chirho = workspace_root_chirho();
    workspace_production_rs_files_chirho()
        .into_iter()
        .filter_map(|path_chirho| {
            let source_chirho = std::fs::read_to_string(&path_chirho).unwrap();
            let production_chirho = production_text_chirho(&source_chirho);
            if !needles_chirho
                .iter()
                .any(|needle_chirho| production_chirho.contains(needle_chirho))
            {
                return None;
            }
            let file_chirho = path_chirho
                .strip_prefix(&root_chirho)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let syntax_chirho = syn::parse_file(&production_chirho)
                .unwrap_or_else(|error_chirho| panic!("parse {file_chirho}: {error_chirho}"));
            Some(ProductionSyntaxChirho {
                file_chirho,
                syntax_chirho,
            })
        })
        .collect()
}

struct TypeNameDetectorChirho<'a> {
    names_chirho: &'a BTreeSet<String>,
    found_chirho: bool,
}

impl<'ast_chirho> Visit<'ast_chirho> for TypeNameDetectorChirho<'_> {
    fn visit_type_path(&mut self, path_chirho: &'ast_chirho syn::TypePath) {
        self.found_chirho |= path_chirho.path.segments.iter().any(|segment_chirho| {
            self.names_chirho
                .contains(&segment_chirho.ident.to_string())
        });
        syn::visit::visit_type_path(self, path_chirho);
    }
}

fn type_contains_names_chirho(type_chirho: &syn::Type, names_chirho: &BTreeSet<String>) -> bool {
    let mut detector_chirho = TypeNameDetectorChirho {
        names_chirho,
        found_chirho: false,
    };
    detector_chirho.visit_type(type_chirho);
    detector_chirho.found_chirho
}

fn collect_use_renames_chirho(
    tree_chirho: &syn::UseTree,
    names_chirho: &BTreeSet<String>,
    found_chirho: &mut BTreeSet<String>,
) {
    match tree_chirho {
        syn::UseTree::Path(path_chirho) => {
            collect_use_renames_chirho(&path_chirho.tree, names_chirho, found_chirho)
        }
        syn::UseTree::Rename(rename_chirho) => {
            if names_chirho.contains(&rename_chirho.ident.to_string()) {
                found_chirho.insert(rename_chirho.rename.to_string());
            }
        }
        syn::UseTree::Group(group_chirho) => {
            for item_chirho in &group_chirho.items {
                collect_use_renames_chirho(item_chirho, names_chirho, found_chirho);
            }
        }
        syn::UseTree::Name(_) | syn::UseTree::Glob(_) => {}
    }
}

struct PostingAliasVisitorChirho<'a> {
    names_chirho: &'a BTreeSet<String>,
    found_chirho: BTreeSet<String>,
}

impl<'ast_chirho> Visit<'ast_chirho> for PostingAliasVisitorChirho<'_> {
    fn visit_item_use(&mut self, use_chirho: &'ast_chirho syn::ItemUse) {
        collect_use_renames_chirho(&use_chirho.tree, self.names_chirho, &mut self.found_chirho);
        syn::visit::visit_item_use(self, use_chirho);
    }

    fn visit_item_type(&mut self, item_chirho: &'ast_chirho syn::ItemType) {
        if type_contains_names_chirho(&item_chirho.ty, self.names_chirho) {
            self.found_chirho.insert(item_chirho.ident.to_string());
        }
        syn::visit::visit_item_type(self, item_chirho);
    }

    fn visit_impl_item_type(&mut self, item_chirho: &'ast_chirho syn::ImplItemType) {
        if type_contains_names_chirho(&item_chirho.ty, self.names_chirho) {
            self.found_chirho.insert(item_chirho.ident.to_string());
        }
        syn::visit::visit_impl_item_type(self, item_chirho);
    }

    fn visit_trait_item_type(&mut self, item_chirho: &'ast_chirho syn::TraitItemType) {
        if item_chirho
            .default
            .as_ref()
            .is_some_and(|(_, type_chirho)| {
                type_contains_names_chirho(type_chirho, self.names_chirho)
            })
        {
            self.found_chirho.insert(item_chirho.ident.to_string());
        }
        syn::visit::visit_trait_item_type(self, item_chirho);
    }
}

fn posting_aliases_chirho(syntax_chirho: &syn::File) -> BTreeSet<String> {
    let mut names_chirho = BTreeSet::from(["PostingChirho".to_string()]);
    loop {
        let mut visitor_chirho = PostingAliasVisitorChirho {
            names_chirho: &names_chirho,
            found_chirho: BTreeSet::new(),
        };
        visitor_chirho.visit_file(syntax_chirho);
        let before_chirho = names_chirho.len();
        names_chirho.extend(visitor_chirho.found_chirho);
        if names_chirho.len() == before_chirho {
            return names_chirho;
        }
    }
}

fn pattern_label_chirho(pattern_chirho: &syn::Pat, index_chirho: usize) -> String {
    match pattern_chirho {
        syn::Pat::Ident(ident_chirho) => ident_chirho.ident.to_string(),
        _ => format!("arg_{index_chirho}_chirho"),
    }
}

struct PostingTypeInventoryVisitorChirho<'a> {
    file_chirho: &'a str,
    aliases_chirho: &'a BTreeSet<String>,
    coordinates_chirho: BTreeMap<PostingTypeCoordinateChirho, usize>,
}

impl PostingTypeInventoryVisitorChirho<'_> {
    fn insert_chirho(&mut self, coordinate_chirho: PostingTypeCoordinateChirho) {
        *self
            .coordinates_chirho
            .entry(coordinate_chirho)
            .or_insert(0) += 1;
    }

    fn collect_signature_chirho(&mut self, owner_chirho: &str, signature_chirho: &syn::Signature) {
        for (index_chirho, input_chirho) in signature_chirho.inputs.iter().enumerate() {
            let syn::FnArg::Typed(input_chirho) = input_chirho else {
                continue;
            };
            if type_contains_names_chirho(&input_chirho.ty, self.aliases_chirho) {
                self.insert_chirho((
                    self.file_chirho.to_string(),
                    owner_chirho.to_string(),
                    "input".to_string(),
                    pattern_label_chirho(&input_chirho.pat, index_chirho),
                ));
            }
        }
        if let syn::ReturnType::Type(_, type_chirho) = &signature_chirho.output {
            if type_contains_names_chirho(type_chirho, self.aliases_chirho) {
                self.insert_chirho((
                    self.file_chirho.to_string(),
                    owner_chirho.to_string(),
                    "return".to_string(),
                    "return_chirho".to_string(),
                ));
            }
        }
    }

    fn collect_fields_chirho(&mut self, owner_chirho: &str, fields_chirho: &syn::Fields) {
        for (index_chirho, field_chirho) in fields_chirho.iter().enumerate() {
            if type_contains_names_chirho(&field_chirho.ty, self.aliases_chirho) {
                self.insert_chirho((
                    self.file_chirho.to_string(),
                    owner_chirho.to_string(),
                    "field".to_string(),
                    field_chirho
                        .ident
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| format!("field_{index_chirho}_chirho")),
                ));
            }
        }
    }
}

impl<'ast_chirho> Visit<'ast_chirho> for PostingTypeInventoryVisitorChirho<'_> {
    fn visit_item_use(&mut self, use_chirho: &'ast_chirho syn::ItemUse) {
        let mut aliases_chirho = BTreeSet::new();
        collect_use_renames_chirho(&use_chirho.tree, self.aliases_chirho, &mut aliases_chirho);
        for alias_chirho in aliases_chirho {
            self.insert_chirho((
                self.file_chirho.to_string(),
                alias_chirho,
                "alias".to_string(),
                "use_chirho".to_string(),
            ));
        }
        syn::visit::visit_item_use(self, use_chirho);
    }

    fn visit_item_fn(&mut self, function_chirho: &'ast_chirho syn::ItemFn) {
        self.collect_signature_chirho(&function_chirho.sig.ident.to_string(), &function_chirho.sig);
        syn::visit::visit_item_fn(self, function_chirho);
    }

    fn visit_impl_item_fn(&mut self, function_chirho: &'ast_chirho syn::ImplItemFn) {
        self.collect_signature_chirho(&function_chirho.sig.ident.to_string(), &function_chirho.sig);
        syn::visit::visit_impl_item_fn(self, function_chirho);
    }

    fn visit_trait_item_fn(&mut self, function_chirho: &'ast_chirho syn::TraitItemFn) {
        self.collect_signature_chirho(&function_chirho.sig.ident.to_string(), &function_chirho.sig);
        syn::visit::visit_trait_item_fn(self, function_chirho);
    }

    fn visit_item_struct(&mut self, item_chirho: &'ast_chirho syn::ItemStruct) {
        self.collect_fields_chirho(&item_chirho.ident.to_string(), &item_chirho.fields);
        syn::visit::visit_item_struct(self, item_chirho);
    }

    fn visit_item_enum(&mut self, item_chirho: &'ast_chirho syn::ItemEnum) {
        for variant_chirho in &item_chirho.variants {
            self.collect_fields_chirho(
                &format!("{}::{}", item_chirho.ident, variant_chirho.ident),
                &variant_chirho.fields,
            );
        }
        syn::visit::visit_item_enum(self, item_chirho);
    }

    fn visit_item_type(&mut self, item_chirho: &'ast_chirho syn::ItemType) {
        if type_contains_names_chirho(&item_chirho.ty, self.aliases_chirho) {
            self.insert_chirho((
                self.file_chirho.to_string(),
                item_chirho.ident.to_string(),
                "alias".to_string(),
                "type_chirho".to_string(),
            ));
        }
        syn::visit::visit_item_type(self, item_chirho);
    }

    fn visit_impl_item_type(&mut self, item_chirho: &'ast_chirho syn::ImplItemType) {
        if type_contains_names_chirho(&item_chirho.ty, self.aliases_chirho) {
            self.insert_chirho((
                self.file_chirho.to_string(),
                item_chirho.ident.to_string(),
                "alias".to_string(),
                "impl_type_chirho".to_string(),
            ));
        }
        syn::visit::visit_impl_item_type(self, item_chirho);
    }

    fn visit_trait_item_type(&mut self, item_chirho: &'ast_chirho syn::TraitItemType) {
        if item_chirho
            .default
            .as_ref()
            .is_some_and(|(_, type_chirho)| {
                type_contains_names_chirho(type_chirho, self.aliases_chirho)
            })
        {
            self.insert_chirho((
                self.file_chirho.to_string(),
                item_chirho.ident.to_string(),
                "alias".to_string(),
                "trait_type_chirho".to_string(),
            ));
        }
        syn::visit::visit_trait_item_type(self, item_chirho);
    }
}

fn posting_type_inventory_for_source_chirho(
    file_chirho: &str,
    syntax_chirho: &syn::File,
) -> BTreeMap<PostingTypeCoordinateChirho, usize> {
    let aliases_chirho = posting_aliases_chirho(syntax_chirho);
    let mut visitor_chirho = PostingTypeInventoryVisitorChirho {
        file_chirho,
        aliases_chirho: &aliases_chirho,
        coordinates_chirho: BTreeMap::new(),
    };
    visitor_chirho.visit_file(syntax_chirho);
    visitor_chirho.coordinates_chirho
}

fn posting_type_inventory_chirho() -> BTreeMap<PostingTypeCoordinateChirho, usize> {
    let mut coordinates_chirho = BTreeMap::new();
    for source_chirho in production_syntaxes_containing_chirho(&["PostingChirho"]) {
        for (coordinate_chirho, count_chirho) in posting_type_inventory_for_source_chirho(
            &source_chirho.file_chirho,
            &source_chirho.syntax_chirho,
        ) {
            *coordinates_chirho.entry(coordinate_chirho).or_insert(0) += count_chirho;
        }
    }
    coordinates_chirho
}

fn collect_family_imports_chirho(
    tree_chirho: &syn::UseTree,
    prefix_chirho: &mut Vec<String>,
    aliases_chirho: &mut BTreeMap<String, String>,
    ledger_module_aliases_chirho: &mut BTreeSet<String>,
    imports_glob_chirho: &mut bool,
    unresolved_chirho: &mut BTreeSet<String>,
) {
    match tree_chirho {
        syn::UseTree::Path(path_chirho) => {
            prefix_chirho.push(path_chirho.ident.to_string());
            collect_family_imports_chirho(
                &path_chirho.tree,
                prefix_chirho,
                aliases_chirho,
                ledger_module_aliases_chirho,
                imports_glob_chirho,
                unresolved_chirho,
            );
            prefix_chirho.pop();
        }
        syn::UseTree::Name(name_chirho) => {
            let name_chirho = name_chirho.ident.to_string();
            let from_ledger_chirho = prefix_chirho
                .iter()
                .any(|part_chirho| part_chirho == "ledger_chirho");
            if name_chirho == "ledger_chirho" {
                ledger_module_aliases_chirho.insert(name_chirho.clone());
            } else if from_ledger_chirho && POSTING_FAMILY_CHIRHO.contains(&name_chirho.as_str()) {
                aliases_chirho.insert(name_chirho.clone(), name_chirho);
            } else if POSTING_FAMILY_CHIRHO.contains(&name_chirho.as_str()) {
                unresolved_chirho.insert(format!("import-target:{name_chirho}"));
            }
        }
        syn::UseTree::Rename(rename_chirho) => {
            let original_chirho = rename_chirho.ident.to_string();
            let alias_chirho = rename_chirho.rename.to_string();
            let aliases_ledger_module_chirho = original_chirho == "ledger_chirho"
                || (original_chirho == "self"
                    && prefix_chirho
                        .last()
                        .is_some_and(|part_chirho| part_chirho == "ledger_chirho"));
            if aliases_ledger_module_chirho {
                ledger_module_aliases_chirho.insert(alias_chirho.clone());
            }
            let from_ledger_chirho = prefix_chirho
                .iter()
                .any(|part_chirho| part_chirho == "ledger_chirho");
            if from_ledger_chirho && POSTING_FAMILY_CHIRHO.contains(&original_chirho.as_str()) {
                aliases_chirho.insert(alias_chirho.clone(), original_chirho);
            } else if POSTING_FAMILY_CHIRHO.contains(&original_chirho.as_str()) {
                unresolved_chirho
                    .insert(format!("import-target:{original_chirho}-as-{alias_chirho}"));
            }
        }
        syn::UseTree::Glob(_) => {
            if prefix_chirho
                .iter()
                .any(|part_chirho| part_chirho == "ledger_chirho")
            {
                *imports_glob_chirho = true;
            }
        }
        syn::UseTree::Group(group_chirho) => {
            for item_chirho in &group_chirho.items {
                collect_family_imports_chirho(
                    item_chirho,
                    prefix_chirho,
                    aliases_chirho,
                    ledger_module_aliases_chirho,
                    imports_glob_chirho,
                    unresolved_chirho,
                );
            }
        }
    }
}

#[derive(Default)]
struct FamilyImportsVisitorChirho {
    aliases_chirho: BTreeMap<String, String>,
    ledger_module_aliases_chirho: BTreeSet<String>,
    imports_glob_chirho: bool,
    unresolved_chirho: BTreeSet<String>,
}

impl<'ast_chirho> Visit<'ast_chirho> for FamilyImportsVisitorChirho {
    fn visit_item_use(&mut self, use_chirho: &'ast_chirho syn::ItemUse) {
        let mut aliases_chirho = BTreeMap::new();
        let mut ledger_module_aliases_chirho = BTreeSet::new();
        let mut imports_glob_chirho = false;
        let mut unresolved_chirho = BTreeSet::new();
        collect_family_imports_chirho(
            &use_chirho.tree,
            &mut Vec::new(),
            &mut aliases_chirho,
            &mut ledger_module_aliases_chirho,
            &mut imports_glob_chirho,
            &mut unresolved_chirho,
        );
        if !matches!(use_chirho.vis, syn::Visibility::Inherited)
            && (!aliases_chirho.is_empty()
                || !ledger_module_aliases_chirho.is_empty()
                || imports_glob_chirho)
        {
            unresolved_chirho.insert("public-posting-family-reexport".to_string());
        }
        self.aliases_chirho.extend(aliases_chirho);
        self.ledger_module_aliases_chirho
            .extend(ledger_module_aliases_chirho);
        self.imports_glob_chirho |= imports_glob_chirho;
        self.unresolved_chirho.extend(unresolved_chirho);
        syn::visit::visit_item_use(self, use_chirho);
    }
}

fn resolve_family_path_chirho(
    path_chirho: &syn::Path,
    root_ledger_file_chirho: bool,
    imports_chirho: &FamilyImportsVisitorChirho,
) -> Result<Option<String>, String> {
    let segments_chirho = path_chirho
        .segments
        .iter()
        .map(|segment_chirho| segment_chirho.ident.to_string())
        .collect::<Vec<_>>();
    let Some(last_chirho) = segments_chirho.last() else {
        return Ok(None);
    };
    if let Some(target_chirho) = imports_chirho.aliases_chirho.get(last_chirho) {
        return Ok(Some(target_chirho.clone()));
    }
    if !POSTING_FAMILY_CHIRHO.contains(&last_chirho.as_str()) {
        return Ok(None);
    }
    let prefix_chirho = &segments_chirho[..segments_chirho.len().saturating_sub(1)];
    if root_ledger_file_chirho
        || imports_chirho.imports_glob_chirho
        || prefix_chirho.iter().any(|part_chirho| {
            part_chirho == "ledger_chirho"
                || imports_chirho
                    .ledger_module_aliases_chirho
                    .contains(part_chirho)
        })
    {
        Ok(Some(last_chirho.clone()))
    } else {
        Err(format!("path:{}", segments_chirho.join("::")))
    }
}

fn macro_family_references_chirho(
    tokens_chirho: proc_macro2::TokenStream,
    imports_chirho: &FamilyImportsVisitorChirho,
    found_chirho: &mut BTreeSet<String>,
) {
    for token_chirho in tokens_chirho {
        match token_chirho {
            proc_macro2::TokenTree::Ident(ident_chirho) => {
                let name_chirho = ident_chirho.to_string();
                if POSTING_FAMILY_CHIRHO.contains(&name_chirho.as_str())
                    || imports_chirho.aliases_chirho.contains_key(&name_chirho)
                {
                    found_chirho.insert(format!("macro-token:{name_chirho}"));
                }
            }
            proc_macro2::TokenTree::Group(group_chirho) => {
                macro_family_references_chirho(group_chirho.stream(), imports_chirho, found_chirho)
            }
            proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => {}
        }
    }
}

struct PostingBodyReferencesVisitorChirho<'a> {
    root_ledger_file_chirho: bool,
    imports_chirho: &'a FamilyImportsVisitorChirho,
    references_chirho: BTreeMap<String, usize>,
    unresolved_chirho: BTreeSet<String>,
}

impl<'ast_chirho> Visit<'ast_chirho> for PostingBodyReferencesVisitorChirho<'_> {
    fn visit_expr_path(&mut self, path_chirho: &'ast_chirho syn::ExprPath) {
        match resolve_family_path_chirho(
            &path_chirho.path,
            self.root_ledger_file_chirho,
            self.imports_chirho,
        ) {
            Ok(Some(callee_chirho)) => {
                *self.references_chirho.entry(callee_chirho).or_insert(0) += 1;
            }
            Err(reference_chirho) => {
                self.unresolved_chirho.insert(reference_chirho);
            }
            Ok(None) => {}
        }
        syn::visit::visit_expr_path(self, path_chirho);
    }

    fn visit_expr_method_call(&mut self, call_chirho: &'ast_chirho syn::ExprMethodCall) {
        let method_chirho = call_chirho.method.to_string();
        if POSTING_FAMILY_CHIRHO.contains(&method_chirho.as_str()) {
            self.unresolved_chirho
                .insert(format!("method:{method_chirho}"));
        }
        syn::visit::visit_expr_method_call(self, call_chirho);
    }

    fn visit_macro(&mut self, macro_chirho: &'ast_chirho syn::Macro) {
        macro_family_references_chirho(
            macro_chirho.tokens.clone(),
            self.imports_chirho,
            &mut self.unresolved_chirho,
        );
        if let Err(reference_chirho) = resolve_family_path_chirho(
            &macro_chirho.path,
            self.root_ledger_file_chirho,
            self.imports_chirho,
        ) {
            self.unresolved_chirho.insert(reference_chirho);
        }
        syn::visit::visit_macro(self, macro_chirho);
    }

    fn visit_item_fn(&mut self, _function_chirho: &'ast_chirho syn::ItemFn) {}

    fn visit_impl_item_fn(&mut self, _function_chirho: &'ast_chirho syn::ImplItemFn) {}
}

struct PostingCallInventoryVisitorChirho<'a> {
    file_chirho: &'a str,
    imports_chirho: &'a FamilyImportsVisitorChirho,
    edges_chirho: BTreeMap<PostingCallEdgeChirho, usize>,
    unresolved_chirho: BTreeSet<String>,
}

impl PostingCallInventoryVisitorChirho<'_> {
    fn collect_block_chirho(&mut self, owner_chirho: &str, block_chirho: &syn::Block) {
        // A function-valued path is conservatively an edge even when it is called later through a
        // local variable or callback, so direct-call syntax is not a guard bypass.
        let mut references_chirho = PostingBodyReferencesVisitorChirho {
            root_ledger_file_chirho: self.file_chirho
                == "src/economic_flows_chirho/ledger_chirho.rs",
            imports_chirho: self.imports_chirho,
            references_chirho: BTreeMap::new(),
            unresolved_chirho: BTreeSet::new(),
        };
        references_chirho.visit_block(block_chirho);
        for (callee_chirho, count_chirho) in references_chirho.references_chirho {
            *self
                .edges_chirho
                .entry((
                    self.file_chirho.to_string(),
                    owner_chirho.to_string(),
                    callee_chirho,
                ))
                .or_insert(0) += count_chirho;
        }
        self.unresolved_chirho
            .extend(references_chirho.unresolved_chirho);
    }
}

impl<'ast_chirho> Visit<'ast_chirho> for PostingCallInventoryVisitorChirho<'_> {
    fn visit_item_fn(&mut self, function_chirho: &'ast_chirho syn::ItemFn) {
        self.collect_block_chirho(
            &function_chirho.sig.ident.to_string(),
            &function_chirho.block,
        );
        syn::visit::visit_item_fn(self, function_chirho);
    }

    fn visit_impl_item_fn(&mut self, function_chirho: &'ast_chirho syn::ImplItemFn) {
        self.collect_block_chirho(
            &function_chirho.sig.ident.to_string(),
            &function_chirho.block,
        );
        syn::visit::visit_impl_item_fn(self, function_chirho);
    }

    fn visit_trait_item_fn(&mut self, function_chirho: &'ast_chirho syn::TraitItemFn) {
        if let Some(block_chirho) = &function_chirho.default {
            self.collect_block_chirho(&function_chirho.sig.ident.to_string(), block_chirho);
        }
        syn::visit::visit_trait_item_fn(self, function_chirho);
    }

    fn visit_item_macro(&mut self, macro_chirho: &'ast_chirho syn::ItemMacro) {
        macro_family_references_chirho(
            macro_chirho.mac.tokens.clone(),
            self.imports_chirho,
            &mut self.unresolved_chirho,
        );
        syn::visit::visit_item_macro(self, macro_chirho);
    }
}

fn posting_call_inventory_for_source_chirho(
    file_chirho: &str,
    syntax_chirho: &syn::File,
) -> (BTreeMap<PostingCallEdgeChirho, usize>, BTreeSet<String>) {
    let mut imports_chirho = FamilyImportsVisitorChirho::default();
    imports_chirho.visit_file(syntax_chirho);
    let mut calls_chirho = PostingCallInventoryVisitorChirho {
        file_chirho,
        imports_chirho: &imports_chirho,
        edges_chirho: BTreeMap::new(),
        unresolved_chirho: imports_chirho.unresolved_chirho.clone(),
    };
    calls_chirho.visit_file(syntax_chirho);
    (calls_chirho.edges_chirho, calls_chirho.unresolved_chirho)
}

fn posting_call_inventory_chirho() -> (
    BTreeMap<PostingCallEdgeChirho, usize>,
    BTreeSet<(String, String)>,
) {
    let mut edges_chirho = BTreeMap::new();
    let mut aliases_chirho = BTreeSet::new();
    for source_chirho in production_syntaxes_containing_chirho(POSTING_FAMILY_CHIRHO) {
        let (source_edges_chirho, source_aliases_chirho) = posting_call_inventory_for_source_chirho(
            &source_chirho.file_chirho,
            &source_chirho.syntax_chirho,
        );
        for (edge_chirho, count_chirho) in source_edges_chirho {
            *edges_chirho.entry(edge_chirho).or_insert(0) += count_chirho;
        }
        aliases_chirho.extend(
            source_aliases_chirho
                .into_iter()
                .map(|alias_chirho| (source_chirho.file_chirho.clone(), alias_chirho)),
        );
    }
    (edges_chirho, aliases_chirho)
}

fn expected_type_coordinates_chirho() -> BTreeSet<PostingTypeCoordinateChirho> {
    EXPECTED_POSTING_TYPE_COORDINATES_CHIRHO
        .iter()
        .map(
            |(file_chirho, owner_chirho, kind_chirho, slot_chirho, _role_chirho)| {
                (
                    (*file_chirho).to_string(),
                    (*owner_chirho).to_string(),
                    (*kind_chirho).to_string(),
                    (*slot_chirho).to_string(),
                )
            },
        )
        .collect()
}

#[test]
fn r6e_posting_type_surface_is_exact_and_has_no_shipped_entry_door_chirho() {
    let inventory_chirho = posting_type_inventory_chirho();
    assert!(
        inventory_chirho.values().all(|count_chirho| *count_chirho == 1),
        "PostingChirho coordinate duplicated; path/owner/slot must remain an exact set: {inventory_chirho:?}"
    );
    assert_eq!(
        inventory_chirho.keys().cloned().collect::<BTreeSet<_>>(),
        expected_type_coordinates_chirho(),
        "PostingChirho-bearing production type surface changed; classify every coordinate by role before accepting it"
    );
}

#[test]
fn r6e_posting_family_edges_are_exact_and_cli_uses_only_checked_gas_path_chirho() {
    let (inventory_chirho, unresolved_chirho) = posting_call_inventory_chirho();
    assert!(
        unresolved_chirho.is_empty(),
        "production posting-family references must resolve to classified target symbols; unresolved forms fail closed: {unresolved_chirho:?}"
    );
    assert!(
        inventory_chirho
            .values()
            .all(|count_chirho| *count_chirho == 1),
        "posting-family edge duplicated; classify the additional call site: {inventory_chirho:?}"
    );
    let edges_chirho = inventory_chirho.keys().cloned().collect::<BTreeSet<_>>();

    // THE POSITIVE FROZEN INVENTORY IS DORMANT. Trigger: V2 emits its door.
    //
    // It used to `assert_eq!` this edge set against a 98-row reviewed manifest. At CF6 wave-1 the V1
    // money door died and the measured edge set is EMPTY -- all eleven `POSTING_FAMILY_CHIRHO` names
    // now have zero production call sites. Re-freezing the manifest at `{}` would assert "these are
    // all the money-door call edges" over a set with no members: it could never go red on any tree,
    // forever, while still reading as coverage in every summary. That is green-by-emptiness on a
    // money guard, which is worse than an absent guard.
    //
    // It is NOT repointable either, and that was measured rather than assumed: V2's door is
    // `append_saga_op_chirho` / `canonical_saga_line_chirho` on a different substrate, so there is no
    // same-shaped successor to aim the manifest at. The manifest and `expected_call_edges_chirho()`
    // were therefore deleted rather than emptied -- recover them from
    // archive-chirho/26-07-26-cf6-wave1-money-spine-chirho when writing the V2 equivalent.
    //
    // The two assertions above and the two below are NOT dormant. They are fail-closed and
    // forbidden-shape checks, and empty is the correct reading for each.

    let cli_edges_chirho = edges_chirho
        .iter()
        .filter(|(file_chirho, _, _)| file_chirho.starts_with("crates/cairn-cli-chirho/"))
        .cloned()
        .collect::<BTreeSet<_>>();
    // SUBSET, not equality, and the change is deliberate. The property is a prohibition -- "no CLI
    // handler may route a caller-derived FROM to an unchecked posting path" -- which an equality
    // expressed only by accident, back when exactly one classified edge existed. As equality it went
    // red the moment that edge died, reporting a *missing* edge as if an *unchecked* one had
    // appeared. As a subset it says what it means and stays correct at empty.
    let classified_cli_edge_chirho = (
        "crates/cairn-cli-chirho/src/cli_helpers_chirho/product_chirho/economic_chirho/ledger_cli_chirho.rs".to_string(),
        "handle_ledger_command_chirho".to_string(),
        "charge_gas_chirho".to_string(),
    );
    assert!(
        cli_edges_chirho
            .iter()
            .all(|edge_chirho| *edge_chirho == classified_cli_edge_chirho),
        "no CLI handler may route caller-derived FROM to an unchecked posting path; meter-run's checked gas debit is the only classified CLI edge: {cli_edges_chirho:?}"
    );
    // `transfer_chirho` STAYS IN `POSTING_FAMILY_CHIRHO` SO THIS LINE CAN STILL SEE IT.
    //
    // The reviewed disposition was "drop `transfer_chirho` from the positive list, keep it in the
    // negative one." Implemented at the ASSERTION level, which is where the distinction is real,
    // because the const is not two lists: `POSTING_FAMILY_CHIRHO` is consulted at eight sites inside
    // the AST visitors that resolve aliases, method calls and paths, and it is what selects which
    // files are parsed at all. Removing the name there would have removed it from THIS check too and
    // left a forbidden-token guard that could never fire -- the exact vacuity the disposition exists
    // to prevent. So the name stays in the family and is excluded from the positive inventory above,
    // which now no longer exists to exclude it from.
    //
    // Worth knowing while reading this: the census is AST-based on exact call identifiers, so the
    // 68 sim-crate FIELDS and locals also spelled `transfer_chirho` cannot reach it -- a field is not
    // an `ExprCall`. The exposure this guards is a real `fn transfer_chirho` being CALLED in
    // production, which is precisely what it should catch.
    assert!(
        !edges_chirho
            .iter()
            .any(|(_, _, callee_chirho)| callee_chirho == "transfer_chirho"),
        "unchecked transfer_chirho must have zero in-workspace production caller edges after R6e"
    );
}

#[test]
fn r6e_drill_is_fixed_source_and_outside_the_production_claim_chirho() {
    let relative_chirho = "examples/seed_replication_drill_root_chirho.rs";
    let path_chirho = workspace_root_chirho().join(relative_chirho);
    assert!(
        !workspace_production_rs_files_chirho().contains(&path_chirho),
        "root examples must remain outside the production-source predicate"
    );
    let source_chirho = std::fs::read_to_string(path_chirho).unwrap();

    // RETARGETED 2026-07-26 at CF6 wave-1. This arm used to require the seeder to call
    // `ledger_chirho::transfer_chirho(` and to label its asset `"mint-chirho"`. Both assertions were
    // LEGITIMATELY stale, not violated: the wave-1 deletion removed the V1 token writer, so the
    // seeder no longer seeds ledger activity, and it says so in its own source rather than hiding the
    // reduction. Left as equality checks they would have reported an intended, documented narrowing
    // as a drill regression.
    //
    // What the drill still proves, and what this arm now pins: the signed-anchor and export path the
    // replica-side fold actually verifies.
    assert!(
        source_chirho.contains("append_gate1_ring_a_anchors_chirho("),
        "drill seeder must still append signed Ring-A anchors for the replica fold to verify"
    );
    assert!(
        source_chirho.contains("export_gate1_anchor_head_replication_chirho("),
        "drill seeder must still export the source-signed anchor head the replica pins"
    );

    // The post-wave-1 money property, as a prohibition rather than an equality, so it stays correct
    // while the ledger family is anchored empty. MIGRATION PATH: when V2 lands and the seeder is
    // taught to seed real ledger activity again, this is the assertion that will fire. That firing
    // is the INTENDED event, not a regression -- retarget it then at the V2 door's own name, and
    // restore a positive assertion that the anchors cover a non-empty ledger family.
    assert!(
        !source_chirho.contains("ledger_chirho"),
        "drill seeder must not reach a money door while the V1 writer is gone and V2 has not landed"
    );
}

#[test]
fn r6e_type_scanner_catches_qualified_posting_chirho() {
    let syntax_chirho =
        syn::parse_file("fn door_chirho(rows_chirho: Vec<ledger_chirho::PostingChirho>) {}")
            .unwrap();
    assert!(
        posting_type_inventory_for_source_chirho("fixture_chirho.rs", &syntax_chirho).contains_key(
            &(
                "fixture_chirho.rs".to_string(),
                "door_chirho".to_string(),
                "input".to_string(),
                "rows_chirho".to_string(),
            )
        )
    );
}

#[test]
fn r6e_type_scanner_catches_lifetime_qualified_slice_chirho() {
    let syntax_chirho =
        syn::parse_file("fn door_chirho<'a>(rows_chirho: &'a [PostingChirho]) {}").unwrap();
    assert!(
        posting_type_inventory_for_source_chirho("fixture_chirho.rs", &syntax_chirho).contains_key(
            &(
                "fixture_chirho.rs".to_string(),
                "door_chirho".to_string(),
                "input".to_string(),
                "rows_chirho".to_string(),
            )
        )
    );
}

#[test]
fn r6e_type_scanner_catches_posting_alias_chirho() {
    let syntax_chirho = syn::parse_file(
        r#"
        use ledger_chirho::PostingChirho as EntryPostingChirho;
        type PostingBatchChirho = Vec<EntryPostingChirho>;
        fn door_chirho(rows_chirho: PostingBatchChirho) {}
        "#,
    )
    .unwrap();
    let inventory_chirho =
        posting_type_inventory_for_source_chirho("fixture_chirho.rs", &syntax_chirho);
    assert!(inventory_chirho.contains_key(&(
        "fixture_chirho.rs".to_string(),
        "PostingBatchChirho".to_string(),
        "alias".to_string(),
        "type_chirho".to_string(),
    )));
    assert!(inventory_chirho.contains_key(&(
        "fixture_chirho.rs".to_string(),
        "door_chirho".to_string(),
        "input".to_string(),
        "rows_chirho".to_string(),
    )));
}

#[test]
fn r6e_edge_scanner_resolves_function_scoped_import_forms_chirho() {
    let syntax_chirho = syn::parse_file(
        r#"
        fn plain_chirho() {
            use crate::ledger_chirho::post_entry_chirho;
            let callback_chirho = post_entry_chirho;
            callback_chirho();
        }
        fn direct_alias_chirho() {
            use crate::ledger_chirho::charge_gas_chirho as debit_chirho;
            let callback_chirho = debit_chirho;
            callback_chirho();
        }
        fn grouped_alias_chirho() {
            use crate::ledger_chirho::{transfer_chirho as move_value_chirho};
            let callback_chirho = move_value_chirho;
            callback_chirho();
        }
        "#,
    )
    .unwrap();
    let (inventory_chirho, unresolved_chirho) =
        posting_call_inventory_for_source_chirho("fixture_chirho.rs", &syntax_chirho);
    assert!(unresolved_chirho.is_empty());
    assert_eq!(
        inventory_chirho.keys().cloned().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            (
                "fixture_chirho.rs".to_string(),
                "direct_alias_chirho".to_string(),
                "charge_gas_chirho".to_string(),
            ),
            (
                "fixture_chirho.rs".to_string(),
                "grouped_alias_chirho".to_string(),
                "transfer_chirho".to_string(),
            ),
            (
                "fixture_chirho.rs".to_string(),
                "plain_chirho".to_string(),
                "post_entry_chirho".to_string(),
            ),
        ])
    );
}

#[test]
fn r6e_edge_scanner_normalizes_posting_family_module_alias_chirho() {
    let syntax_chirho = syn::parse_file(
        r#"
        use crate::ledger_chirho::{self as ledger_ops_chirho};
        fn door_chirho() { (ledger_ops_chirho::transfer_chirho)(); }
        "#,
    )
    .unwrap();
    let (inventory_chirho, unresolved_chirho) =
        posting_call_inventory_for_source_chirho("fixture_chirho.rs", &syntax_chirho);
    assert!(unresolved_chirho.is_empty());
    assert_eq!(
        inventory_chirho.keys().cloned().collect::<BTreeSet<_>>(),
        BTreeSet::from([(
            "fixture_chirho.rs".to_string(),
            "door_chirho".to_string(),
            "transfer_chirho".to_string(),
        )])
    );
}

#[test]
fn r6e_edge_scanner_resolves_relative_prefixes_chirho() {
    for (path_chirho, target_chirho) in [
        ("self::ledger_chirho::transfer_chirho", "transfer_chirho"),
        (
            "super::ledger_chirho::transfer_checked_chirho",
            "transfer_checked_chirho",
        ),
        (
            "crate::economic_flows_chirho::ledger_chirho::charge_gas_chirho",
            "charge_gas_chirho",
        ),
    ] {
        let syntax_chirho = syn::parse_file(&format!(
            "fn door_chirho() {{ let callback_chirho = {path_chirho}; callback_chirho(); }}"
        ))
        .unwrap();
        let (inventory_chirho, unresolved_chirho) =
            posting_call_inventory_for_source_chirho("fixture_chirho.rs", &syntax_chirho);
        assert!(unresolved_chirho.is_empty());
        assert_eq!(
            inventory_chirho.keys().cloned().collect::<BTreeSet<_>>(),
            BTreeSet::from([(
                "fixture_chirho.rs".to_string(),
                "door_chirho".to_string(),
                target_chirho.to_string(),
            )])
        );
    }
}

#[test]
fn r6e_edge_scanner_resolves_function_scoped_glob_chirho() {
    let syntax_chirho = syn::parse_file(
        r#"
        fn door_chirho() {
            use crate::ledger_chirho::*;
            let callback_chirho = charge_gas_chirho;
            callback_chirho();
        }
        "#,
    )
    .unwrap();
    let (inventory_chirho, unresolved_chirho) =
        posting_call_inventory_for_source_chirho("fixture_chirho.rs", &syntax_chirho);
    assert!(unresolved_chirho.is_empty());
    assert_eq!(
        inventory_chirho.keys().cloned().collect::<BTreeSet<_>>(),
        BTreeSet::from([(
            "fixture_chirho.rs".to_string(),
            "door_chirho".to_string(),
            "charge_gas_chirho".to_string(),
        )])
    );
}

#[test]
fn r6e_edge_scanner_fails_closed_on_reexport_chain_and_macro_body_chirho() {
    for source_chirho in [
        r#"
        pub use crate::ledger_chirho::transfer_chirho;
        fn door_chirho() { relay_chirho::transfer_chirho(); }
        "#,
        r#"
        macro_rules! post_chirho {
            () => { crate::ledger_chirho::transfer_chirho(); };
        }
        "#,
    ] {
        let syntax_chirho = syn::parse_file(source_chirho).unwrap();
        let (_, unresolved_chirho) =
            posting_call_inventory_for_source_chirho("fixture_chirho.rs", &syntax_chirho);
        assert!(
            !unresolved_chirho.is_empty(),
            "re-export and macro indirection must fail closed for classification"
        );
    }
}

#[test]
fn r6e_edge_scanner_exercises_unresolvable_reference_failure_chirho() {
    let syntax_chirho =
        syn::parse_file("fn door_chirho() { mystery_chirho::transfer_chirho(); }").unwrap();
    let (inventory_chirho, unresolved_chirho) =
        posting_call_inventory_for_source_chirho("fixture_chirho.rs", &syntax_chirho);
    assert!(inventory_chirho.is_empty());
    assert_eq!(
        unresolved_chirho,
        BTreeSet::from(["path:mystery_chirho::transfer_chirho".to_string()])
    );
}
