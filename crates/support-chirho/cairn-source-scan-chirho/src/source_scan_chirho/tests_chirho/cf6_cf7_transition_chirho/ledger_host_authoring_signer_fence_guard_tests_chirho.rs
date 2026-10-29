// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The ledger-host config-authoring program's inheritance fence: no brick in it may accept a
//! caller-supplied `HostLedgerSignersChirho`.
//!
//! Its own file rather than another section of the regenesis guard file, because it has one subject
//! and that file had already grown past the size the structure report signals on. Splitting was the
//! signal's intended response; adding a third of a file to it would have been the other one.

use super::cf6_regenesis_guard_tests_chirho::{
    attributes_are_test_only_chirho, REGENESIS_CRATE_CHIRHO,
};
use super::{production_text_chirho, workspace_root_chirho};
use std::collections::BTreeSet;
use syn::visit::Visit;

/// Every place a caller-supplied `HostLedgerSignersChirho` could enter the operator regenesis
/// crate, resolved through the AST rather than matched as text.
///
/// Two shapes, because a text census would see only the first: a PARAMETER on a crate-external
/// function, and a `pub` FIELD an outside caller could fill with a struct literal. The type walk
/// recurses into references, generics, tuples, and bounds, so `Option<&HostLedgerSignersChirho>`
/// and `&[HostLedgerSignersChirho]` are found exactly as the bare form is.
#[derive(Default)]
struct SignerSetSurfaceChirho {
    public_function_parameters_chirho: BTreeSet<String>,
    public_struct_fields_chirho: BTreeSet<String>,
    /// The positive control's population: every function parameter of this type at ANY visibility.
    /// The crate really does pass the loaded set into its own pin derivations, so an empty set here
    /// means the walker is broken and every absence assertion below is vacuous.
    any_function_parameters_chirho: BTreeSet<String>,
}

const RUNTIME_SIGNER_SET_TYPE_CHIRHO: &str = "HostLedgerSignersChirho";

fn type_mentions_ident_chirho(type_chirho: &syn::Type, ident_chirho: &str) -> bool {
    match type_chirho {
        syn::Type::Path(path_chirho) => {
            if let Some(qself_chirho) = &path_chirho.qself {
                if type_mentions_ident_chirho(&qself_chirho.ty, ident_chirho) {
                    return true;
                }
            }
            path_chirho.path.segments.iter().any(|segment_chirho| {
                if segment_chirho.ident == ident_chirho {
                    return true;
                }
                match &segment_chirho.arguments {
                    syn::PathArguments::AngleBracketed(arguments_chirho) => {
                        arguments_chirho.args.iter().any(|argument_chirho| {
                            matches!(argument_chirho, syn::GenericArgument::Type(inner_chirho)
                                if type_mentions_ident_chirho(inner_chirho, ident_chirho))
                        })
                    }
                    syn::PathArguments::Parenthesized(arguments_chirho) => {
                        arguments_chirho.inputs.iter().any(|input_chirho| {
                            type_mentions_ident_chirho(input_chirho, ident_chirho)
                        }) || matches!(&arguments_chirho.output, syn::ReturnType::Type(_, inner_chirho)
                                if type_mentions_ident_chirho(inner_chirho, ident_chirho))
                    }
                    syn::PathArguments::None => false,
                }
            })
        }
        syn::Type::Reference(reference_chirho) => {
            type_mentions_ident_chirho(&reference_chirho.elem, ident_chirho)
        }
        syn::Type::Ptr(pointer_chirho) => {
            type_mentions_ident_chirho(&pointer_chirho.elem, ident_chirho)
        }
        syn::Type::Slice(slice_chirho) => {
            type_mentions_ident_chirho(&slice_chirho.elem, ident_chirho)
        }
        syn::Type::Array(array_chirho) => {
            type_mentions_ident_chirho(&array_chirho.elem, ident_chirho)
        }
        syn::Type::Paren(paren_chirho) => {
            type_mentions_ident_chirho(&paren_chirho.elem, ident_chirho)
        }
        syn::Type::Group(group_chirho) => {
            type_mentions_ident_chirho(&group_chirho.elem, ident_chirho)
        }
        syn::Type::Tuple(tuple_chirho) => tuple_chirho
            .elems
            .iter()
            .any(|element_chirho| type_mentions_ident_chirho(element_chirho, ident_chirho)),
        syn::Type::ImplTrait(bounds_chirho) => {
            type_bounds_mention_ident_chirho(&bounds_chirho.bounds, ident_chirho)
        }
        syn::Type::TraitObject(bounds_chirho) => {
            type_bounds_mention_ident_chirho(&bounds_chirho.bounds, ident_chirho)
        }
        _ => false,
    }
}

fn type_bounds_mention_ident_chirho(
    bounds_chirho: &syn::punctuated::Punctuated<syn::TypeParamBound, syn::Token![+]>,
    ident_chirho: &str,
) -> bool {
    bounds_chirho.iter().any(|bound_chirho| {
        matches!(bound_chirho, syn::TypeParamBound::Trait(trait_chirho)
            if trait_chirho
                .path
                .segments
                .iter()
                .any(|segment_chirho| segment_chirho.ident == ident_chirho))
    })
}

struct SignerSetSurfaceVisitorChirho<'a> {
    file_chirho: &'a str,
    surface_chirho: &'a mut SignerSetSurfaceChirho,
}

impl SignerSetSurfaceVisitorChirho<'_> {
    fn record_signature_chirho(
        &mut self,
        name_chirho: &str,
        is_public_chirho: bool,
        inputs_chirho: &syn::punctuated::Punctuated<syn::FnArg, syn::Token![,]>,
    ) {
        let takes_chirho = inputs_chirho.iter().any(|argument_chirho| {
            matches!(argument_chirho, syn::FnArg::Typed(typed_chirho)
                if type_mentions_ident_chirho(&typed_chirho.ty, RUNTIME_SIGNER_SET_TYPE_CHIRHO))
        });
        if !takes_chirho {
            return;
        }
        let site_chirho = format!("{}::{name_chirho}", self.file_chirho);
        self.surface_chirho
            .any_function_parameters_chirho
            .insert(site_chirho.clone());
        if is_public_chirho {
            self.surface_chirho
                .public_function_parameters_chirho
                .insert(site_chirho);
        }
    }
}

impl<'ast_chirho> Visit<'ast_chirho> for SignerSetSurfaceVisitorChirho<'_> {
    fn visit_item_fn(&mut self, function_chirho: &'ast_chirho syn::ItemFn) {
        if attributes_are_test_only_chirho(&function_chirho.attrs) {
            return;
        }
        self.record_signature_chirho(
            &function_chirho.sig.ident.to_string(),
            matches!(function_chirho.vis, syn::Visibility::Public(_)),
            &function_chirho.sig.inputs,
        );
        syn::visit::visit_item_fn(self, function_chirho);
    }

    fn visit_impl_item_fn(&mut self, function_chirho: &'ast_chirho syn::ImplItemFn) {
        if attributes_are_test_only_chirho(&function_chirho.attrs) {
            return;
        }
        self.record_signature_chirho(
            &function_chirho.sig.ident.to_string(),
            matches!(function_chirho.vis, syn::Visibility::Public(_)),
            &function_chirho.sig.inputs,
        );
        syn::visit::visit_impl_item_fn(self, function_chirho);
    }

    fn visit_item_struct(&mut self, structure_chirho: &'ast_chirho syn::ItemStruct) {
        if attributes_are_test_only_chirho(&structure_chirho.attrs) {
            return;
        }
        for field_chirho in structure_chirho.fields.iter() {
            if !matches!(field_chirho.vis, syn::Visibility::Public(_)) {
                continue;
            }
            if !type_mentions_ident_chirho(&field_chirho.ty, RUNTIME_SIGNER_SET_TYPE_CHIRHO) {
                continue;
            }
            let field_name_chirho = field_chirho
                .ident
                .as_ref()
                .map(|ident_chirho| ident_chirho.to_string())
                .unwrap_or_else(|| "<tuple-field-chirho>".to_owned());
            self.surface_chirho
                .public_struct_fields_chirho
                .insert(format!(
                    "{}::{}::{field_name_chirho}",
                    self.file_chirho, structure_chirho.ident
                ));
        }
        syn::visit::visit_item_struct(self, structure_chirho);
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
}

fn regenesis_signer_set_surface_chirho() -> SignerSetSurfaceChirho {
    let source_root_chirho = workspace_root_chirho()
        .join(REGENESIS_CRATE_CHIRHO)
        .join("src");
    let mut files_chirho = std::fs::read_dir(&source_root_chirho)
        .unwrap()
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap();
    files_chirho.sort_by_key(|entry_chirho| entry_chirho.file_name());
    let mut surface_chirho = SignerSetSurfaceChirho::default();
    for entry_chirho in files_chirho {
        let path_chirho = entry_chirho.path();
        if path_chirho
            .extension()
            .and_then(|value_chirho| value_chirho.to_str())
            != Some("rs")
        {
            continue;
        }
        let file_name_chirho = path_chirho
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let source_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        let parsed_chirho = syn::parse_file(&source_chirho).unwrap();
        let mut visitor_chirho = SignerSetSurfaceVisitorChirho {
            file_chirho: &file_name_chirho,
            surface_chirho: &mut surface_chirho,
        };
        visitor_chirho.visit_file(&parsed_chirho);
    }
    surface_chirho
}

/// **The config-author program's inheritance fence, pinned so it cannot be quietly optimized away.**
///
/// The ruling behind this guard: no brick in the ledger-host config-authoring program may accept a
/// CALLER-SUPPLIED `HostLedgerSignersChirho`; every road that needs the six runtime signers must
/// LOAD them itself.
///
/// **The reason this guard was written has since been closed at the type — and the guard still
/// stands, deliberately.** When it was written, that type's six fields were `pub` and the struct was
/// not `#[non_exhaustive]`, so a set could be RE-ASSEMBLED field by field from a DIFFERENT root's
/// loaded signers, and holding one proved only that SOME root's secrets loaded. The seal brick made
/// the fields `pub(crate)` with per-role shared-borrow accessors, so that re-assembly is now
/// rejected by the compiler for every crate but `cairn-ledger-host-chirho` itself. Two things keep
/// this guard load-bearing anyway: the seal's residual is in-crate (a module inside the host crate
/// can still overwrite one role on a set it loaded), and a caller-supplied set would still let the
/// CALLER choose which root's custody a derivation runs against, which is a separate property from
/// whether the set was honestly assembled. So the natural optimization that would destroy it — a
/// later brick taking the signers as a parameter to save a load — is exactly what this guard
/// refuses, and it refuses it for a reason the seal does not supply.
///
/// **Scope, stated because a wider claim would be false.** This is about the OPERATOR REGENESIS
/// CRATE's boundary, not the workspace: the served ledger-host runtime legitimately passes a loaded
/// set between its own functions, and a workspace-wide version of this assertion would be red at
/// every one of those sites while saying nothing about this program. What makes the narrow form
/// sufficient is that the program's exported roads all live in this crate, so a caller in another
/// crate — including the later CLI brick — has no signature to hand a set to.
#[test]
fn regenesis_exposes_no_caller_supplied_runtime_signer_set_chirho() {
    let surface_chirho = regenesis_signer_set_surface_chirho();

    // Positive control. The crate really does thread the loaded set into its own pin derivations,
    // so a walker that found nothing would make both absence assertions below vacuously green.
    assert!(
        surface_chirho.any_function_parameters_chirho.len() >= 2,
        "the signer-set parameter walk found {} sites; it must find the crate's own internal ones \
         or every absence assertion here is vacuous",
        surface_chirho.any_function_parameters_chirho.len()
    );

    assert!(
        surface_chirho.public_function_parameters_chirho.is_empty(),
        "a crate-external signature now accepts a caller-supplied HostLedgerSignersChirho, so a \
         caller could hand over a set re-assembled from another root's secrets and have it pass as \
         custody: {:?}",
        surface_chirho.public_function_parameters_chirho
    );
    assert!(
        surface_chirho.public_struct_fields_chirho.is_empty(),
        "a public struct field now carries a HostLedgerSignersChirho, which is the same \
         caller-supplied road as a parameter with an extra step: {:?}",
        surface_chirho.public_struct_fields_chirho
    );
}

/// The emission brick's own half of the fence: the emission road must reach the six runtime signers
/// ONLY through the custody road, so its module names that type nowhere at all.
///
/// It is a tripwire rather than a live constraint today — emission has no present need of the
/// signers — and that is precisely when a constraint gets optimized away, by a later author who
/// wants to avoid a second load and reaches for the obvious parameter.
///
/// The three presence assertions at the end are STRUCTURAL, and are labelled as such because they
/// cannot prove behaviour: no unit test can observe an `fsync`, and the atomic half of the
/// no-overwrite law only fires in a race a test cannot schedule. The behavioural arms live in the
/// crate's own emission tests; these three exist so that DELETING one of the three calls is loud.
#[test]
fn regenesis_emission_reaches_the_signer_set_only_through_the_custody_road_chirho() {
    let emission_source_chirho = std::fs::read_to_string(
        workspace_root_chirho()
            .join(REGENESIS_CRATE_CHIRHO)
            .join("src/ledger_host_artifact_emission_chirho.rs"),
    )
    .unwrap();
    let production_chirho = production_text_chirho(&emission_source_chirho);

    // Positive control: this really is the emission road, and it really does go through custody.
    assert!(
        production_chirho.contains("bind_custody_and_derive_ledger_host_artifacts_chirho("),
        "the emission module must author through the custody road (positive control — a renamed or \
         moved module would make every assertion below a statement about the wrong file)"
    );
    assert!(
        production_chirho.contains("pub fn author_and_emit_ledger_host_artifacts_chirho("),
        "the emission road is missing or renamed (positive control)"
    );

    assert!(
        !production_chirho.contains(RUNTIME_SIGNER_SET_TYPE_CHIRHO),
        "the emission module now names HostLedgerSignersChirho; it must obtain the six runtime \
         signers only by calling the custody road, never by receiving or rebuilding a set"
    );

    for required_chirho in ["create_new(true)", "mode(0o600)", "sync_all("] {
        assert!(
            production_chirho.contains(required_chirho),
            "the emission write path lost a custody or durability call that no unit test can \
             observe directly: {required_chirho}"
        );
    }
}
