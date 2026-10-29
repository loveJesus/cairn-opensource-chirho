// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Brick #6's structural half: the ledger-host authoring PORCELAIN cannot report on a document it
//! has not derived, cannot mint, and accepts no argument that carries an authority.
//!
//! **Why the derive-before-print rule needs a guard rather than review.** The parse road returns a
//! document with ZERO money-policy validation — a mint of 10,000 against a ceiling of 2,000 passes
//! it in full — and the document is already sitting in a local variable two lines above the report.
//! Wiring the report to it would compile, would read like a simplification ("we already have the
//! inputs, why thread the derived plan through?"), and would silently turn an operator report into
//! a statement nothing checked. So the property is expressed as a TYPE — neither report builder
//! takes the document — and this guard refuses a signature that reopens it.
//!
//! **HONEST SCOPE.** This guard is about SIGNATURES and about the ARGUMENT SURFACE. It cannot prove
//! that a derivation actually ran: that is the behavioural arm
//! `neither_verb_reports_on_a_document_it_has_not_derived_chirho` in the CLI crate, which drives the
//! real verbs over a real over-mint document. Nor can it prove custody keeps a test-kind issuer out
//! of production — no source census can, because that is a property of which secrets exist on a
//! root. Read the two together: the arm proves the behaviour today, this guard makes the shape that
//! produced it non-negotiable tomorrow.

use super::{production_text_chirho, workspace_root_chirho};
use std::collections::BTreeMap;
use syn::visit::Visit;

/// The porcelain and the argument module it parses into. Named as paths rather than resolved by
/// search, so a MOVED module fails loudly here instead of silently shrinking this guard's subject.
const AUTHORING_CLI_MODULE_CHIRHO: &str =
    "crates/cairn-cli-chirho/src/cli_helpers_chirho/operations_chirho/ledger_host_author_cli_chirho.rs";
const AUTHORING_CLI_ARGS_MODULE_CHIRHO: &str =
    "crates/cairn-cli-chirho/src/args_chirho/core_chirho/ops_args_chirho.rs";

/// The reviewed document type. A report builder that names this in its signature can print a money
/// statement nothing validated.
const AUTHORING_INPUTS_TYPE_CHIRHO: &str = "LedgerHostAuthoringInputsV1Chirho";
/// The two types that exist only downstream of a custody-bound derivation. One of them is what each
/// report builder must take instead.
const DERIVED_ARTIFACTS_TYPE_CHIRHO: &str = "LedgerHostAuthoredArtifactsChirho";
const EMITTED_ARTIFACTS_TYPE_CHIRHO: &str = "LedgerHostEmittedArtifactsChirho";

const REVIEW_REPORT_BUILDER_CHIRHO: &str = "ledger_host_author_review_report_chirho";
const EMISSION_REPORT_BUILDER_CHIRHO: &str = "ledger_host_author_report_chirho";

/// The un-derived read road. Its presence is the positive control for the whole guard: if the
/// porcelain stopped calling it, the hazard this guard is shaped around would not exist here and
/// every assertion below would be about the wrong file.
const UNDERIVED_READ_ROAD_CHIRHO: &str =
    "read_ledger_host_authoring_inputs_money_policy_unchecked_chirho(";

/// Every function signature in the porcelain, keyed by name, with the type names it mentions.
/// Resolved through the AST rather than matched as text, so `&LedgerHostAuthoredArtifactsChirho`,
/// `Option<&...>`, and a tuple of them are all found the same way a bare mention is.
#[derive(Default)]
struct AuthoringCliSignatureCensusChirho {
    signatures_chirho: BTreeMap<String, Vec<String>>,
}

struct AuthoringCliSignatureVisitorChirho<'a> {
    census_chirho: &'a mut AuthoringCliSignatureCensusChirho,
}

impl AuthoringCliSignatureVisitorChirho<'_> {
    fn record_chirho(&mut self, signature_chirho: &syn::Signature) {
        let mut mentions_chirho = Vec::new();
        for argument_chirho in &signature_chirho.inputs {
            if let syn::FnArg::Typed(typed_chirho) = argument_chirho {
                collect_type_idents_chirho(&typed_chirho.ty, &mut mentions_chirho);
            }
        }
        if let syn::ReturnType::Type(_arrow_chirho, return_type_chirho) = &signature_chirho.output {
            collect_type_idents_chirho(return_type_chirho, &mut mentions_chirho);
        }
        self.census_chirho
            .signatures_chirho
            .insert(signature_chirho.ident.to_string(), mentions_chirho);
    }
}

impl<'ast_chirho> Visit<'ast_chirho> for AuthoringCliSignatureVisitorChirho<'_> {
    fn visit_item_fn(&mut self, function_chirho: &'ast_chirho syn::ItemFn) {
        self.record_chirho(&function_chirho.sig);
        syn::visit::visit_item_fn(self, function_chirho);
    }

    fn visit_impl_item_fn(&mut self, function_chirho: &'ast_chirho syn::ImplItemFn) {
        self.record_chirho(&function_chirho.sig);
        syn::visit::visit_impl_item_fn(self, function_chirho);
    }
}

/// Collect every path segment identifier a type mentions, recursing through references, generics,
/// tuples, slices, and trait bounds. A census keyed on the OUTERMOST name would miss
/// `Option<&LedgerHostAuthoringInputsV1Chirho>`, which is the shape a later author would reach for.
fn collect_type_idents_chirho(type_chirho: &syn::Type, into_chirho: &mut Vec<String>) {
    match type_chirho {
        syn::Type::Path(path_chirho) => {
            if let Some(qself_chirho) = &path_chirho.qself {
                collect_type_idents_chirho(&qself_chirho.ty, into_chirho);
            }
            for segment_chirho in &path_chirho.path.segments {
                into_chirho.push(segment_chirho.ident.to_string());
                match &segment_chirho.arguments {
                    syn::PathArguments::AngleBracketed(arguments_chirho) => {
                        for argument_chirho in &arguments_chirho.args {
                            if let syn::GenericArgument::Type(inner_chirho) = argument_chirho {
                                collect_type_idents_chirho(inner_chirho, into_chirho);
                            }
                        }
                    }
                    syn::PathArguments::Parenthesized(arguments_chirho) => {
                        for input_chirho in &arguments_chirho.inputs {
                            collect_type_idents_chirho(input_chirho, into_chirho);
                        }
                        if let syn::ReturnType::Type(_arrow_chirho, inner_chirho) =
                            &arguments_chirho.output
                        {
                            collect_type_idents_chirho(inner_chirho, into_chirho);
                        }
                    }
                    syn::PathArguments::None => {}
                }
            }
        }
        syn::Type::Reference(reference_chirho) => {
            collect_type_idents_chirho(&reference_chirho.elem, into_chirho)
        }
        syn::Type::Ptr(pointer_chirho) => {
            collect_type_idents_chirho(&pointer_chirho.elem, into_chirho)
        }
        syn::Type::Slice(slice_chirho) => {
            collect_type_idents_chirho(&slice_chirho.elem, into_chirho)
        }
        syn::Type::Array(array_chirho) => {
            collect_type_idents_chirho(&array_chirho.elem, into_chirho)
        }
        syn::Type::Paren(paren_chirho) => {
            collect_type_idents_chirho(&paren_chirho.elem, into_chirho)
        }
        syn::Type::Group(group_chirho) => {
            collect_type_idents_chirho(&group_chirho.elem, into_chirho)
        }
        syn::Type::Tuple(tuple_chirho) => {
            for element_chirho in &tuple_chirho.elems {
                collect_type_idents_chirho(element_chirho, into_chirho);
            }
        }
        syn::Type::ImplTrait(bounds_chirho) => {
            collect_bound_idents_chirho(&bounds_chirho.bounds, into_chirho)
        }
        syn::Type::TraitObject(bounds_chirho) => {
            collect_bound_idents_chirho(&bounds_chirho.bounds, into_chirho)
        }
        _other_chirho => {}
    }
}

fn collect_bound_idents_chirho(
    bounds_chirho: &syn::punctuated::Punctuated<syn::TypeParamBound, syn::Token![+]>,
    into_chirho: &mut Vec<String>,
) {
    for bound_chirho in bounds_chirho {
        if let syn::TypeParamBound::Trait(trait_chirho) = bound_chirho {
            for segment_chirho in &trait_chirho.path.segments {
                into_chirho.push(segment_chirho.ident.to_string());
            }
        }
    }
}

fn authoring_cli_production_source_chirho() -> String {
    let path_chirho = workspace_root_chirho().join(AUTHORING_CLI_MODULE_CHIRHO);
    let raw_chirho = std::fs::read_to_string(&path_chirho).unwrap_or_else(|error_chirho| {
        panic!(
            "the ledger-host authoring porcelain is missing or moved ({}): {error_chirho}",
            path_chirho.display()
        )
    });
    production_text_chirho(&raw_chirho).into_owned()
}

/// Extract one `pub struct` block from the CLI argument module, so an assertion about the authoring
/// argument surface cannot accidentally read a neighbouring command's fields.
fn args_struct_block_chirho(source_chirho: &str, struct_name_chirho: &str) -> String {
    let start_chirho = source_chirho
        .find(&format!("pub struct {struct_name_chirho}"))
        .unwrap_or_else(|| {
            panic!("the authoring argument struct is missing or renamed: {struct_name_chirho}")
        });
    let tail_chirho = &source_chirho[start_chirho..];
    let end_chirho = tail_chirho
        .find("\n}\n")
        .unwrap_or_else(|| panic!("could not find the end of {struct_name_chirho}"))
        + 3;
    tail_chirho[..end_chirho].to_owned()
}

/// **THE DERIVE-BEFORE-PRINT INVARIANT, executed.** Neither report builder may see the reviewed
/// document; each must take a value that exists only downstream of a custody-bound derivation.
#[test]
fn the_authoring_cli_report_builders_cannot_see_an_underived_document_chirho() {
    let source_chirho = authoring_cli_production_source_chirho();

    // POSITIVE CONTROLS, before any absence assertion. The porcelain must really call the
    // un-derived read road (otherwise the hazard is not here and this guard guards nothing), and
    // both report builders must exist by name (otherwise a rename makes every check below vacuous).
    assert!(
        source_chirho.contains(UNDERIVED_READ_ROAD_CHIRHO),
        "the authoring porcelain no longer calls the un-derived read road, so this guard is \
         reasoning about a hazard that has moved: re-point it at whatever now parses the reviewed \
         document before a report is built"
    );

    let syntax_chirho = syn::parse_file(&source_chirho).expect("parse the authoring porcelain");
    let mut census_chirho = AuthoringCliSignatureCensusChirho::default();
    AuthoringCliSignatureVisitorChirho {
        census_chirho: &mut census_chirho,
    }
    .visit_file(&syntax_chirho);
    assert!(
        census_chirho.signatures_chirho.len() >= 5,
        "the signature walk found only {} functions in the authoring porcelain; it must find the \
         module's real functions or every absence assertion here is vacuous",
        census_chirho.signatures_chirho.len()
    );

    for builder_chirho in [REVIEW_REPORT_BUILDER_CHIRHO, EMISSION_REPORT_BUILDER_CHIRHO] {
        assert!(
            census_chirho.signatures_chirho.contains_key(builder_chirho),
            "a report builder this guard reasons about is missing or renamed: {builder_chirho}"
        );
    }

    // THE INVARIANT. No signature anywhere in the porcelain may take or return the reviewed
    // document, so no printer can be wired to it.
    let document_takers_chirho: Vec<&String> = census_chirho
        .signatures_chirho
        .iter()
        .filter(|(_name_chirho, mentions_chirho)| {
            mentions_chirho
                .iter()
                .any(|mention_chirho| mention_chirho == AUTHORING_INPUTS_TYPE_CHIRHO)
        })
        .map(|(name_chirho, _mentions_chirho)| name_chirho)
        .collect();
    assert!(
        document_takers_chirho.is_empty(),
        "a function in the ledger-host authoring porcelain now takes or returns \
         {AUTHORING_INPUTS_TYPE_CHIRHO}: {document_takers_chirho:?}. That type carries ZERO \
         money-policy validation — a document minting above its ceiling parses into it in full — so \
         a report built from it shows an operator a money statement nothing checked. Build reports \
         from the derived artifacts instead."
    );

    // And the other direction: each builder must actually take a derived value, or the absence
    // above could be satisfied by a builder that takes nothing at all and reads a global.
    let review_mentions_chirho = &census_chirho.signatures_chirho[REVIEW_REPORT_BUILDER_CHIRHO];
    assert!(
        review_mentions_chirho
            .iter()
            .any(|mention_chirho| mention_chirho == DERIVED_ARTIFACTS_TYPE_CHIRHO),
        "the review report builder must take {DERIVED_ARTIFACTS_TYPE_CHIRHO}, which exists only \
         downstream of a custody-bound derivation; it mentions {review_mentions_chirho:?}"
    );
    let emission_mentions_chirho = &census_chirho.signatures_chirho[EMISSION_REPORT_BUILDER_CHIRHO];
    assert!(
        emission_mentions_chirho
            .iter()
            .any(|mention_chirho| mention_chirho == EMITTED_ARTIFACTS_TYPE_CHIRHO),
        "the emission report builder must take {EMITTED_ARTIFACTS_TYPE_CHIRHO}, which exists only \
         downstream of a completed emission; it mentions {emission_mentions_chirho:?}"
    );
}

/// **NEVER MINT, AND TAKE ONLY UNTRUSTED INPUTS — brick #4's question, asked of the CLI.**
///
/// The porcelain must contain no key-creation road, and the authoring argument surface must carry
/// no field through which a caller could hand this program an authority it never proved: a verifier
/// pin, a loaded signer set, an already-derived artifacts value, or a pre-built test-kind marker.
#[test]
fn the_authoring_cli_never_mints_and_takes_no_authority_bearing_input_chirho() {
    let source_chirho = authoring_cli_production_source_chirho();

    // Positive control: this really is the porcelain, and it really does reach the authoring roads.
    assert!(
        source_chirho.contains("author_and_emit_ledger_host_artifacts_chirho(")
            && source_chirho.contains("bind_custody_and_derive_ledger_host_artifacts_chirho("),
        "the authoring porcelain must call both authoring roads (positive control — a renamed or \
         moved module would make every assertion below a statement about the wrong file)"
    );

    for forbidden_chirho in [
        "OsRng",
        "::generate",
        "set_secret_chirho(",
        "SigningKey",
        "HostLedgerSignersChirho",
    ] {
        assert!(
            !source_chirho.contains(forbidden_chirho),
            "the ledger-host authoring porcelain now names `{forbidden_chirho}`. This surface \
             accepts pre-provisioned secrets by NAME and refuses when one is absent; a CLI that can \
             create or assemble a key is a CLI that can silently invent an authority."
        );
    }

    let args_source_chirho =
        std::fs::read_to_string(workspace_root_chirho().join(AUTHORING_CLI_ARGS_MODULE_CHIRHO))
            .expect("read the CLI argument module");
    for struct_chirho in [
        "LedgerHostAuthoringCoordinatesArgsChirho",
        "LedgerHostAuthorArgsChirho",
        "LedgerHostAuthorReviewArgsChirho",
    ] {
        let block_chirho = args_struct_block_chirho(&args_source_chirho, struct_chirho);
        for forbidden_chirho in [
            "verifying",
            "_hex_chirho",
            "SignersChirho",
            "ArtifactsChirho",
            "MarkerConfigChirho",
            "SigningKey",
        ] {
            assert!(
                !block_chirho.contains(forbidden_chirho),
                "the authoring argument struct {struct_chirho} now carries `{forbidden_chirho}`. \
                 Every argument here must be an UNTRUSTED input — a path, a secret NAME, a digest \
                 to check, a port, or a choice between two branches — because anything else lets a \
                 caller hand this program an authority nothing behind it proved."
            );
        }
        assert!(
            !block_chirho.contains("default_value"),
            "the authoring argument struct {struct_chirho} now defaults a coordinate. These \
             arguments are written into, or select the posture of, a reviewed authority artifact; a \
             defaulted coordinate is one nobody reviewed, and a defaulted MODE is how a missing \
             argument decides a money question."
        );
    }

    // The coordinates struct is where the mode lives, so name that expectation explicitly rather
    // than leaving it implicit in the loop above.
    let coordinates_block_chirho = args_struct_block_chirho(
        &args_source_chirho,
        "LedgerHostAuthoringCoordinatesArgsChirho",
    );
    assert!(
        coordinates_block_chirho.contains("mode_chirho: LedgerHostAuthoringModeArgChirho"),
        "the authoring coordinates must carry a REQUIRED, non-optional mode; an `Option` or an \
         absent field would let an invocation author a production artifact by omission"
    );
    assert!(
        coordinates_block_chirho.contains("issuer_secret_name_chirho: String"),
        "the authoring coordinates must select the issuer by SECRET NAME (positive control for the \
         forbidden-token scan above, which would pass vacuously against an empty block)"
    );
}
