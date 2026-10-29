// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Typed production JSONL discovery, including logical populations without fixed filenames.

use super::{
    production_text_chirho, workspace_production_rs_files_chirho, workspace_relative_chirho,
};
use std::collections::{BTreeMap, BTreeSet};
use syn::visit::Visit;
use syn::{Expr, ExprLit, ExprMethodCall, ItemConst, Lit};

pub const REFS_REFLOG_LOGICAL_SURFACE_CHIRHO: &str = "refs.reflog-chirho";

const DYNAMIC_JSONL_MUTATION_SURFACE_SUFFIX_CHIRHO: &str = "_DYNAMIC_JSONL_MUTATION_SURFACE_CHIRHO";
const REQUIRED_DYNAMIC_JSONL_POPULATIONS_CHIRHO: &[&str] = &[REFS_REFLOG_LOGICAL_SURFACE_CHIRHO];
const DECLARED_DYNAMIC_JSONL_POPULATIONS_CHIRHO: &[&str] = &[REFS_REFLOG_LOGICAL_SURFACE_CHIRHO];

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProductionJsonlLogicalSurfaceChirho {
    LiteralRootFileChirho { file_name_chirho: String },
    DynamicPerBranchPopulationChirho { logical_name_chirho: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionJsonlLogicalSurfaceInventoryChirho {
    surfaces_chirho: BTreeSet<ProductionJsonlLogicalSurfaceChirho>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionJsonlLogicalSurfaceCoverageGapsChirho {
    pub literal_root_files_chirho: BTreeSet<String>,
    pub dynamic_per_branch_populations_chirho: BTreeSet<String>,
}

impl ProductionJsonlLogicalSurfaceInventoryChirho {
    pub fn surfaces_chirho(
        &self,
    ) -> impl ExactSizeIterator<Item = &ProductionJsonlLogicalSurfaceChirho> {
        self.surfaces_chirho.iter()
    }

    pub fn literal_root_files_chirho(&self) -> BTreeSet<&str> {
        self.surfaces_chirho
            .iter()
            .filter_map(|surface_chirho| match surface_chirho {
                ProductionJsonlLogicalSurfaceChirho::LiteralRootFileChirho { file_name_chirho } => {
                    Some(file_name_chirho.as_str())
                }
                ProductionJsonlLogicalSurfaceChirho::DynamicPerBranchPopulationChirho {
                    ..
                } => None,
            })
            .collect()
    }

    pub fn dynamic_per_branch_populations_chirho(&self) -> BTreeSet<&str> {
        self.surfaces_chirho
            .iter()
            .filter_map(|surface_chirho| match surface_chirho {
                ProductionJsonlLogicalSurfaceChirho::LiteralRootFileChirho { .. } => None,
                ProductionJsonlLogicalSurfaceChirho::DynamicPerBranchPopulationChirho {
                    logical_name_chirho,
                } => Some(logical_name_chirho.as_str()),
            })
            .collect()
    }

    pub fn coverage_gaps_chirho(
        &self,
        literal_root_file_reviewed_chirho: impl Fn(&str) -> bool,
        dynamic_population_reviewed_chirho: impl Fn(&str) -> bool,
    ) -> ProductionJsonlLogicalSurfaceCoverageGapsChirho {
        let mut gaps_chirho = ProductionJsonlLogicalSurfaceCoverageGapsChirho {
            literal_root_files_chirho: BTreeSet::new(),
            dynamic_per_branch_populations_chirho: BTreeSet::new(),
        };
        for surface_chirho in &self.surfaces_chirho {
            match surface_chirho {
                ProductionJsonlLogicalSurfaceChirho::LiteralRootFileChirho { file_name_chirho }
                    if !literal_root_file_reviewed_chirho(file_name_chirho) =>
                {
                    gaps_chirho
                        .literal_root_files_chirho
                        .insert(file_name_chirho.clone());
                }
                ProductionJsonlLogicalSurfaceChirho::DynamicPerBranchPopulationChirho {
                    logical_name_chirho,
                } if !dynamic_population_reviewed_chirho(logical_name_chirho) => {
                    gaps_chirho
                        .dynamic_per_branch_populations_chirho
                        .insert(logical_name_chirho.clone());
                }
                _ => {}
            }
        }
        gaps_chirho
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DynamicJsonlMutationSourceChirho {
    file_chirho: String,
    logical_name_chirho: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
// The Chirho suffix is the project's naming convention, so the shared-postfix lint cannot apply.
#[allow(clippy::enum_variant_names)]
enum DynamicJsonlPopulationValidationErrorChirho {
    MissingDeclarationChirho {
        logical_name_chirho: String,
    },
    DuplicateDeclarationChirho {
        logical_name_chirho: String,
        count_chirho: usize,
    },
    UnexpectedDeclarationChirho {
        logical_name_chirho: String,
    },
    MissingMutationSourceChirho {
        logical_name_chirho: String,
    },
    UndeclaredMutationSourceChirho {
        file_chirho: String,
        logical_name_chirho: String,
    },
    MalformedMutationSourceChirho {
        file_chirho: String,
    },
}

#[derive(Default)]
struct ProductionJsonlSourceVisitorChirho {
    file_chirho: String,
    literal_root_files_chirho: BTreeSet<String>,
    dynamic_mutation_sources_chirho: Vec<DynamicJsonlMutationSourceChirho>,
    /// Same-file `const NAME: &str = "…-chirho.jsonl"` items, so `root_chirho.join(NAME)` counts
    /// as the literal it names. Without this a log whose name lives in a const was invisible to
    /// every inventory guard — a whole syntactic form silently excluded (found 2026-09-09 when
    /// five new publication logs left the guards green with nothing claimed; it then surfaced
    /// eight placement-authority logs that had never been reviewed).
    ///
    /// Known residual: a const used from ANOTHER file (`super::NAME`, an imported name) is not
    /// resolved. Measured 2026-09-09: 91 production `root_chirho.join(IDENT)` sites, 70 same-file;
    /// the 21 cross-file sites all name directories or sit in test modules, so no production log
    /// is behind the residual today. Widen to a workspace const table when one is.
    string_consts_chirho: BTreeMap<String, String>,
}

impl ProductionJsonlSourceVisitorChirho {
    fn receiver_is_root_chirho(receiver_chirho: &Expr) -> bool {
        let Expr::Path(path_chirho) = receiver_chirho else {
            return false;
        };
        path_chirho.qself.is_none()
            && path_chirho.path.segments.len() == 1
            && path_chirho.path.segments[0].ident == "root_chirho"
    }

    fn string_literal_chirho(expression_chirho: &Expr) -> Option<String> {
        let Expr::Lit(ExprLit {
            lit: Lit::Str(literal_chirho),
            ..
        }) = expression_chirho
        else {
            return None;
        };
        Some(literal_chirho.value())
    }

    /// A string literal, or a single-segment path naming a same-file string const.
    fn string_literal_or_const_chirho(&self, expression_chirho: &Expr) -> Option<String> {
        if let Some(literal_chirho) = Self::string_literal_chirho(expression_chirho) {
            return Some(literal_chirho);
        }
        let Expr::Path(path_chirho) = expression_chirho else {
            return None;
        };
        if path_chirho.qself.is_some() || path_chirho.path.segments.len() != 1 {
            return None;
        }
        self.string_consts_chirho
            .get(&path_chirho.path.segments[0].ident.to_string())
            .cloned()
    }

    /// Consts first, so a `join(NAME)` that precedes `const NAME` in the file still resolves.
    fn collect_string_consts_chirho(&mut self, file_chirho: &syn::File) {
        for item_chirho in &file_chirho.items {
            if let syn::Item::Const(item_chirho) = item_chirho {
                if let Some(value_chirho) = Self::string_literal_chirho(item_chirho.expr.as_ref()) {
                    self.string_consts_chirho
                        .insert(item_chirho.ident.to_string(), value_chirho);
                }
            }
        }
    }

    fn scan_file_chirho(&mut self, file_chirho: &syn::File) {
        self.collect_string_consts_chirho(file_chirho);
        self.visit_file(file_chirho);
    }
}

impl<'ast> Visit<'ast> for ProductionJsonlSourceVisitorChirho {
    fn visit_expr_method_call(&mut self, call_chirho: &'ast ExprMethodCall) {
        if call_chirho.method == "join"
            && Self::receiver_is_root_chirho(&call_chirho.receiver)
            && call_chirho.args.len() == 1
        {
            if let Some(file_name_chirho) = call_chirho
                .args
                .first()
                .and_then(|argument_chirho| self.string_literal_or_const_chirho(argument_chirho))
            {
                if file_name_chirho.ends_with("-chirho.jsonl") {
                    self.literal_root_files_chirho.insert(file_name_chirho);
                }
            }
        }
        syn::visit::visit_expr_method_call(self, call_chirho);
    }

    fn visit_item_const(&mut self, item_chirho: &'ast ItemConst) {
        if item_chirho
            .ident
            .to_string()
            .ends_with(DYNAMIC_JSONL_MUTATION_SURFACE_SUFFIX_CHIRHO)
        {
            self.dynamic_mutation_sources_chirho
                .push(DynamicJsonlMutationSourceChirho {
                    file_chirho: self.file_chirho.clone(),
                    logical_name_chirho: Self::string_literal_chirho(item_chirho.expr.as_ref()),
                });
        }
        syn::visit::visit_item_const(self, item_chirho);
    }
}

fn validate_dynamic_populations_chirho(
    declarations_chirho: &[&str],
    mutation_sources_chirho: &[DynamicJsonlMutationSourceChirho],
) -> Result<BTreeSet<String>, DynamicJsonlPopulationValidationErrorChirho> {
    let mut declaration_counts_chirho = BTreeMap::<String, usize>::new();
    for logical_name_chirho in declarations_chirho {
        *declaration_counts_chirho
            .entry((*logical_name_chirho).to_string())
            .or_default() += 1;
    }

    for (logical_name_chirho, count_chirho) in &declaration_counts_chirho {
        if *count_chirho != 1 {
            return Err(
                DynamicJsonlPopulationValidationErrorChirho::DuplicateDeclarationChirho {
                    logical_name_chirho: logical_name_chirho.clone(),
                    count_chirho: *count_chirho,
                },
            );
        }
    }
    for required_chirho in REQUIRED_DYNAMIC_JSONL_POPULATIONS_CHIRHO {
        if !declaration_counts_chirho.contains_key(*required_chirho) {
            return Err(
                DynamicJsonlPopulationValidationErrorChirho::MissingDeclarationChirho {
                    logical_name_chirho: (*required_chirho).to_string(),
                },
            );
        }
    }
    for logical_name_chirho in declaration_counts_chirho.keys() {
        if !REQUIRED_DYNAMIC_JSONL_POPULATIONS_CHIRHO.contains(&logical_name_chirho.as_str()) {
            return Err(
                DynamicJsonlPopulationValidationErrorChirho::UnexpectedDeclarationChirho {
                    logical_name_chirho: logical_name_chirho.clone(),
                },
            );
        }
    }
    let mut mutation_source_counts_chirho = BTreeMap::<String, usize>::new();
    for mutation_source_chirho in mutation_sources_chirho {
        let Some(logical_name_chirho) = &mutation_source_chirho.logical_name_chirho else {
            return Err(
                DynamicJsonlPopulationValidationErrorChirho::MalformedMutationSourceChirho {
                    file_chirho: mutation_source_chirho.file_chirho.clone(),
                },
            );
        };
        if !declaration_counts_chirho.contains_key(logical_name_chirho) {
            return Err(
                DynamicJsonlPopulationValidationErrorChirho::UndeclaredMutationSourceChirho {
                    file_chirho: mutation_source_chirho.file_chirho.clone(),
                    logical_name_chirho: logical_name_chirho.clone(),
                },
            );
        }
        *mutation_source_counts_chirho
            .entry(logical_name_chirho.clone())
            .or_default() += 1;
    }
    for logical_name_chirho in declaration_counts_chirho.keys() {
        if !mutation_source_counts_chirho.contains_key(logical_name_chirho) {
            return Err(
                DynamicJsonlPopulationValidationErrorChirho::MissingMutationSourceChirho {
                    logical_name_chirho: logical_name_chirho.clone(),
                },
            );
        }
    }
    Ok(declaration_counts_chirho.into_keys().collect())
}

fn scan_production_jsonl_sources_chirho() -> ProductionJsonlSourceVisitorChirho {
    let mut inventory_chirho = ProductionJsonlSourceVisitorChirho::default();
    for path_chirho in workspace_production_rs_files_chirho() {
        let file_chirho = workspace_relative_chirho(&path_chirho);
        let text_chirho = std::fs::read_to_string(&path_chirho)
            .unwrap_or_else(|error_chirho| panic!("failed to read {file_chirho}: {error_chirho}"));
        let production_chirho = production_text_chirho(&text_chirho);
        let syntax_chirho = syn::parse_file(&production_chirho).unwrap_or_else(|error_chirho| {
            panic!("failed to parse production source {file_chirho}: {error_chirho}")
        });
        let mut visitor_chirho = ProductionJsonlSourceVisitorChirho {
            file_chirho,
            ..ProductionJsonlSourceVisitorChirho::default()
        };
        visitor_chirho.scan_file_chirho(&syntax_chirho);
        inventory_chirho
            .literal_root_files_chirho
            .append(&mut visitor_chirho.literal_root_files_chirho);
        inventory_chirho
            .dynamic_mutation_sources_chirho
            .append(&mut visitor_chirho.dynamic_mutation_sources_chirho);
    }
    inventory_chirho
}

pub fn production_jsonl_logical_surface_inventory_chirho(
) -> ProductionJsonlLogicalSurfaceInventoryChirho {
    let source_inventory_chirho = scan_production_jsonl_sources_chirho();
    let dynamic_populations_chirho = validate_dynamic_populations_chirho(
        DECLARED_DYNAMIC_JSONL_POPULATIONS_CHIRHO,
        &source_inventory_chirho.dynamic_mutation_sources_chirho,
    )
    .unwrap_or_else(|error_chirho| {
        panic!("invalid production dynamic JSONL population inventory: {error_chirho:?}")
    });
    let mut surfaces_chirho = source_inventory_chirho
        .literal_root_files_chirho
        .into_iter()
        .map(
            |file_name_chirho| ProductionJsonlLogicalSurfaceChirho::LiteralRootFileChirho {
                file_name_chirho,
            },
        )
        .collect::<BTreeSet<_>>();
    surfaces_chirho.extend(
        dynamic_populations_chirho
            .into_iter()
            .map(|logical_name_chirho| {
                ProductionJsonlLogicalSurfaceChirho::DynamicPerBranchPopulationChirho {
                    logical_name_chirho,
                }
            }),
    );
    ProductionJsonlLogicalSurfaceInventoryChirho { surfaces_chirho }
}

/// Compatibility boundary for callers that still assume every production JSONL surface is one
/// literal root filename. It refuses once any dynamic population exists so completeness cannot go
/// green by silently flattening or omitting a population.
pub fn production_root_jsonl_log_names_chirho() -> BTreeSet<String> {
    let inventory_chirho = production_jsonl_logical_surface_inventory_chirho();
    let dynamic_chirho = inventory_chirho.dynamic_per_branch_populations_chirho();
    assert!(
        dynamic_chirho.is_empty(),
        "filename-only production JSONL census cannot represent dynamic populations {dynamic_chirho:?}; migrate this completeness caller to production_jsonl_logical_surface_inventory_chirho"
    );
    inventory_chirho
        .literal_root_files_chirho()
        .into_iter()
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    fn previous_literal_root_file_census_chirho() -> BTreeSet<String> {
        let mut names_chirho = BTreeSet::new();
        for path_chirho in workspace_production_rs_files_chirho() {
            let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
            let production_chirho = production_text_chirho(&text_chirho);
            let mut rest_chirho = production_chirho.as_ref();
            while let Some((_before_chirho, after_chirho)) =
                rest_chirho.split_once("root_chirho.join(\"")
            {
                let Some((name_chirho, next_chirho)) = after_chirho.split_once('"') else {
                    break;
                };
                if name_chirho.ends_with("-chirho.jsonl") {
                    names_chirho.insert(name_chirho.to_string());
                }
                rest_chirho = next_chirho;
            }
        }
        names_chirho
    }

    fn scan_fixture_chirho(source_chirho: &str) -> ProductionJsonlSourceVisitorChirho {
        let syntax_chirho = syn::parse_file(source_chirho).unwrap();
        let mut visitor_chirho = ProductionJsonlSourceVisitorChirho {
            file_chirho: "fixture_chirho.rs".to_string(),
            ..ProductionJsonlSourceVisitorChirho::default()
        };
        visitor_chirho.scan_file_chirho(&syntax_chirho);
        visitor_chirho
    }

    #[test]
    fn production_inventory_keeps_literals_and_one_dynamic_reflog_population_chirho() {
        let inventory_chirho = production_jsonl_logical_surface_inventory_chirho();
        let literal_chirho = inventory_chirho.literal_root_files_chirho();
        assert!(!literal_chirho.is_empty());
        assert!(literal_chirho.contains("reflog-chirho.jsonl"));
        assert_eq!(
            inventory_chirho.dynamic_per_branch_populations_chirho(),
            BTreeSet::from([REFS_REFLOG_LOGICAL_SURFACE_CHIRHO])
        );
        assert_eq!(
            inventory_chirho
                .surfaces_chirho()
                .filter(|surface_chirho| matches!(
                    surface_chirho,
                    ProductionJsonlLogicalSurfaceChirho::DynamicPerBranchPopulationChirho { .. }
                ))
                .count(),
            1
        );
    }

    #[test]
    fn shipping_reflog_mutation_owner_declares_dynamic_population_chirho() {
        let source_inventory_chirho = scan_production_jsonl_sources_chirho();
        assert!(
            source_inventory_chirho
                .dynamic_mutation_sources_chirho
                .iter()
                .any(|source_chirho| {
                    source_chirho.file_chirho == "crates/cairn-core-chirho/src/refs_chirho.rs"
                        && source_chirho.logical_name_chirho.as_deref()
                            == Some(REFS_REFLOG_LOGICAL_SURFACE_CHIRHO)
                }),
            "the canonical shipping reflog owner must carry the typed dynamic-population marker"
        );
    }

    /// Every `-chirho.jsonl` name declared as a string `const` in production text, and every one
    /// that appears as a `.join("…")` argument on any line — two text instruments independent of
    /// the `syn` visitor, used only to EXPLAIN the visitor's delta over the old single-line census.
    /// A const declaration is read from its `const ` up to its `;`, because rustfmt wraps
    /// `pub(crate) const NAME: &str =` and its value onto two lines, and a line-oriented reading
    /// missed exactly one production log that way on the day this was written.
    fn text_declared_and_joined_log_names_chirho() -> (BTreeSet<String>, BTreeSet<String>) {
        let mut declared_chirho = BTreeSet::new();
        let mut joined_chirho = BTreeSet::new();
        for path_chirho in workspace_production_rs_files_chirho() {
            let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
            let production_chirho = production_text_chirho(&text_chirho);
            for line_chirho in production_chirho.lines() {
                let trimmed_chirho = line_chirho.trim_start();
                if trimmed_chirho.starts_with(".join(\"") {
                    if let Some(name_chirho) = quoted_log_name_chirho(trimmed_chirho) {
                        joined_chirho.insert(name_chirho);
                    }
                }
            }
            let mut rest_chirho = production_chirho.as_ref();
            while let Some((_before_chirho, after_chirho)) = rest_chirho.split_once("const ") {
                let Some((declaration_chirho, next_chirho)) = after_chirho.split_once(';') else {
                    break;
                };
                if declaration_chirho.contains("str") && !declaration_chirho.contains('{') {
                    if let Some(name_chirho) = quoted_log_name_chirho(declaration_chirho) {
                        declared_chirho.insert(name_chirho);
                    }
                }
                rest_chirho = next_chirho;
            }
        }
        (declared_chirho, joined_chirho)
    }

    fn quoted_log_name_chirho(line_chirho: &str) -> Option<String> {
        let (_before_chirho, after_chirho) = line_chirho.split_once('"')?;
        let (name_chirho, _rest_chirho) = after_chirho.split_once('"')?;
        name_chirho
            .ends_with("-chirho.jsonl")
            .then(|| name_chirho.to_string())
    }

    #[test]
    fn structured_literal_discovery_retains_old_census_and_explains_every_delta_member_chirho() {
        let inventory_chirho = production_jsonl_logical_surface_inventory_chirho();
        let actual_chirho = inventory_chirho
            .literal_root_files_chirho()
            .into_iter()
            .map(str::to_string)
            .collect::<BTreeSet<_>>();
        let previous_chirho = previous_literal_root_file_census_chirho();
        assert!(
            previous_chirho.is_subset(&actual_chirho),
            "structured discovery must retain every literal found by the prior text scanner"
        );
        let delta_chirho = actual_chirho
            .difference(&previous_chirho)
            .cloned()
            .collect::<BTreeSet<_>>();
        // The delta is not enumerated by name — that list grows with the codebase. Each member
        // must instead be explained by one of the two mechanisms the old single-line text census
        // could not see: a `.join("name")` whose receiver sits on the previous line, or a name
        // that lives in a `const`. Anything else is an unexplained discovery and fails here.
        let (declared_chirho, joined_chirho) = text_declared_and_joined_log_names_chirho();
        let unexplained_chirho = delta_chirho
            .iter()
            .filter(|name_chirho| {
                !declared_chirho.contains(*name_chirho) && !joined_chirho.contains(*name_chirho)
            })
            .cloned()
            .collect::<BTreeSet<_>>();
        assert!(
            unexplained_chirho.is_empty(),
            "delta members neither const-declared nor multiline-joined: {unexplained_chirho:?}"
        );
        assert!(
            delta_chirho.contains("gate1-authority-log-chirho.jsonl")
                && joined_chirho.contains("gate1-authority-log-chirho.jsonl"),
            "the known multiline root_chirho/.join call must still be the multiline exemplar"
        );
        // A member that is const-declared AND literal-joined somewhere (gate1 is both) would
        // satisfy a plain intersection with const resolution deleted; only a member reachable
        // through a const alone proves the visitor still resolves them.
        let const_only_chirho = delta_chirho
            .iter()
            .filter(|name_chirho| {
                declared_chirho.contains(*name_chirho) && !joined_chirho.contains(*name_chirho)
            })
            .count();
        assert!(
            const_only_chirho > 0,
            "the const mechanism must be exercised by at least one production log reachable only \
             through a const (it found 17 on 2026-09-09); zero means the visitor stopped \
             resolving consts, not that they left"
        );
    }

    #[test]
    fn missing_dynamic_reflog_declaration_reddens_chirho() {
        assert_eq!(
            validate_dynamic_populations_chirho(&[], &[]),
            Err(
                DynamicJsonlPopulationValidationErrorChirho::MissingDeclarationChirho {
                    logical_name_chirho: REFS_REFLOG_LOGICAL_SURFACE_CHIRHO.to_string(),
                }
            )
        );
    }

    #[test]
    fn duplicate_dynamic_reflog_declaration_reddens_chirho() {
        assert_eq!(
            validate_dynamic_populations_chirho(
                &[
                    REFS_REFLOG_LOGICAL_SURFACE_CHIRHO,
                    REFS_REFLOG_LOGICAL_SURFACE_CHIRHO,
                ],
                &[],
            ),
            Err(
                DynamicJsonlPopulationValidationErrorChirho::DuplicateDeclarationChirho {
                    logical_name_chirho: REFS_REFLOG_LOGICAL_SURFACE_CHIRHO.to_string(),
                    count_chirho: 2,
                }
            )
        );
    }

    #[test]
    fn declared_population_without_mutation_source_reddens_chirho() {
        assert_eq!(
            validate_dynamic_populations_chirho(DECLARED_DYNAMIC_JSONL_POPULATIONS_CHIRHO, &[]),
            Err(
                DynamicJsonlPopulationValidationErrorChirho::MissingMutationSourceChirho {
                    logical_name_chirho: REFS_REFLOG_LOGICAL_SURFACE_CHIRHO.to_string(),
                }
            )
        );
    }

    #[test]
    fn undeclared_dynamic_mutation_source_reddens_chirho() {
        let fixture_chirho = scan_fixture_chirho(
            r#"
const UNREVIEWED_DYNAMIC_JSONL_MUTATION_SURFACE_CHIRHO: &str =
    "refs.unreviewed-chirho";
fn mutate_chirho() {}
"#,
        );
        assert_eq!(
            validate_dynamic_populations_chirho(
                DECLARED_DYNAMIC_JSONL_POPULATIONS_CHIRHO,
                &fixture_chirho.dynamic_mutation_sources_chirho,
            ),
            Err(
                DynamicJsonlPopulationValidationErrorChirho::UndeclaredMutationSourceChirho {
                    file_chirho: "fixture_chirho.rs".to_string(),
                    logical_name_chirho: "refs.unreviewed-chirho".to_string(),
                }
            )
        );
    }

    #[test]
    fn non_literal_dynamic_mutation_marker_reddens_chirho() {
        let fixture_chirho = scan_fixture_chirho(
            r#"
const LOGICAL_SURFACE_CHIRHO: &str = "refs.reflog-chirho";
const REFLOG_DYNAMIC_JSONL_MUTATION_SURFACE_CHIRHO: &str = LOGICAL_SURFACE_CHIRHO;
fn mutate_chirho() {}
"#,
        );
        assert_eq!(
            validate_dynamic_populations_chirho(
                DECLARED_DYNAMIC_JSONL_POPULATIONS_CHIRHO,
                &fixture_chirho.dynamic_mutation_sources_chirho,
            ),
            Err(
                DynamicJsonlPopulationValidationErrorChirho::MalformedMutationSourceChirho {
                    file_chirho: "fixture_chirho.rs".to_string(),
                }
            )
        );
    }

    #[test]
    fn declared_dynamic_mutation_source_is_a_live_positive_control_chirho() {
        let fixture_chirho = scan_fixture_chirho(
            r#"
const REFLOG_DYNAMIC_JSONL_MUTATION_SURFACE_CHIRHO: &str =
    "refs.reflog-chirho";
fn mutate_chirho() {}
"#,
        );
        assert_eq!(
            validate_dynamic_populations_chirho(
                DECLARED_DYNAMIC_JSONL_POPULATIONS_CHIRHO,
                &fixture_chirho.dynamic_mutation_sources_chirho,
            ),
            Ok(BTreeSet::from([
                REFS_REFLOG_LOGICAL_SURFACE_CHIRHO.to_string()
            ]))
        );
    }

    #[test]
    fn multiple_reviewed_mutation_sources_for_one_population_are_allowed_chirho() {
        let fixture_chirho = scan_fixture_chirho(
            r#"
const FIRST_DYNAMIC_JSONL_MUTATION_SURFACE_CHIRHO: &str =
    "refs.reflog-chirho";
const SECOND_DYNAMIC_JSONL_MUTATION_SURFACE_CHIRHO: &str =
    "refs.reflog-chirho";
"#,
        );
        assert_eq!(
            validate_dynamic_populations_chirho(
                DECLARED_DYNAMIC_JSONL_POPULATIONS_CHIRHO,
                &fixture_chirho.dynamic_mutation_sources_chirho,
            ),
            Ok(BTreeSet::from([
                REFS_REFLOG_LOGICAL_SURFACE_CHIRHO.to_string()
            ]))
        );
    }

    #[test]
    fn literal_scanner_uses_rust_syntax_not_comments_or_string_contents_chirho() {
        let fixture_chirho = scan_fixture_chirho(
            r#"
fn fixture_chirho(root_chirho: &std::path::Path) {
    let _kept_chirho = root_chirho.join("kept-chirho.jsonl");
    let _comment_chirho = "root_chirho.join(\"not-code-chirho.jsonl\")";
    // let _ignored_chirho = root_chirho.join("comment-chirho.jsonl");
}
"#,
        );
        assert_eq!(
            fixture_chirho.literal_root_files_chirho,
            BTreeSet::from(["kept-chirho.jsonl".to_string()])
        );
    }

    #[test]
    fn literal_scanner_resolves_same_file_string_consts_chirho() {
        let fixture_chirho = scan_fixture_chirho(
            r#"
fn early_chirho(root_chirho: &std::path::Path) {
    let _before_chirho = root_chirho.join(EARLY_FILE_CHIRHO);
}
const EARLY_FILE_CHIRHO: &str = "early-chirho.jsonl";
const LATE_FILE_CHIRHO: &str = "late-chirho.jsonl";
const NOT_A_LOG_CHIRHO: &str = "late-chirho.redb";
fn late_chirho(root_chirho: &std::path::Path) {
    let _after_chirho = root_chirho.join(LATE_FILE_CHIRHO);
    let _other_chirho = root_chirho.join(NOT_A_LOG_CHIRHO);
    let _unknown_chirho = root_chirho.join(UNKNOWN_FROM_ELSEWHERE_CHIRHO);
}
"#,
        );
        assert_eq!(
            fixture_chirho.literal_root_files_chirho,
            BTreeSet::from(["early-chirho.jsonl".to_string(), "late-chirho.jsonl".to_string()]),
            "a const used before or after its definition resolves; a non-jsonl const and an unknown ident do not"
        );
    }

    #[test]
    fn filename_only_compatibility_boundary_reddens_on_dynamic_population_chirho() {
        let panic_chirho = std::panic::catch_unwind(production_root_jsonl_log_names_chirho)
            .expect_err("filename-only compatibility API must reject dynamic populations");
        let message_chirho = panic_chirho
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic_chirho.downcast_ref::<&str>().copied())
            .unwrap_or("");
        assert!(message_chirho.contains(REFS_REFLOG_LOGICAL_SURFACE_CHIRHO));
        assert!(message_chirho.contains("filename-only"));
    }
}
