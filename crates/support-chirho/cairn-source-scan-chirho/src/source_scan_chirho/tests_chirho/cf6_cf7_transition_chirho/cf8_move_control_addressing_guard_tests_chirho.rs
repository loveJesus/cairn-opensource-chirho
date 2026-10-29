// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)
//! Pins the address-from-canonical-bytes chain behind CF8 move-control substitution safety.
//!
//! The typed equality checks in tenant replay are refactor backstops. Ordinary bad bytes refuse
//! earlier because the domain writer supplies the verified record digest, publication binds that
//! address to `BLAKE3(bytes)`, and reading independently binds retained bytes to the filename. A
//! permanent test that disables both enforcement layers merely to reach the backstop would exercise
//! a world the product never ships. This guard instead fails at the refactor that would make the
//! backstop reachable, while direct behavioral arms pin both address checks in their normal paths.

use crate::source_scan_chirho::workspace_root_chirho;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, ExprCall, ExprMethodCall, Item, ItemFn, Stmt};

const MOVE_CONTROL_STORE_PATH_CHIRHO: &str = "crates/stores-chirho/cairn-tenant-placement-authority-chirho/src/attestation_stores_chirho/move_control_store_chirho.rs";
const CONTENT_ADDRESSED_NAMESPACE_PATH_CHIRHO: &str =
    "crates/support-chirho/cairn-durable-chirho/src/content_addressed_namespace_chirho.rs";

fn parse_source_chirho(path_chirho: &str) -> syn::File {
    let source_chirho = std::fs::read_to_string(workspace_root_chirho().join(path_chirho))
        .unwrap_or_else(|error_chirho| panic!("read {path_chirho}: {error_chirho}"));
    syn::parse_file(&source_chirho)
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

fn path_is_chirho(expression_chirho: &Expr, ident_chirho: &str) -> bool {
    match expression_chirho {
        Expr::Path(path_chirho) => path_chirho.path.is_ident(ident_chirho),
        Expr::Group(group_chirho) => path_is_chirho(&group_chirho.expr, ident_chirho),
        Expr::Paren(paren_chirho) => path_is_chirho(&paren_chirho.expr, ident_chirho),
        Expr::Reference(reference_chirho) => path_is_chirho(&reference_chirho.expr, ident_chirho),
        _ => false,
    }
}

#[derive(Default)]
struct DomainWriterCallVisitorChirho {
    publisher_calls_chirho: usize,
    digest_bound_calls_chirho: usize,
}

impl<'ast> Visit<'ast> for DomainWriterCallVisitorChirho {
    fn visit_expr_call(&mut self, call_chirho: &'ast ExprCall) {
        let publisher_chirho = matches!(
            call_chirho.func.as_ref(),
            Expr::Path(path_chirho)
                if path_chirho
                    .path
                    .segments
                    .last()
                    .is_some_and(|segment_chirho| {
                        segment_chirho.ident
                            == "publish_content_addressed_namespace_file_no_replace_chirho"
                    })
        );
        if publisher_chirho {
            self.publisher_calls_chirho += 1;
            let digest_bound_chirho = call_chirho.args.len() == 5
                && matches!(
                    call_chirho.args.iter().nth(2),
                    Some(Expr::MethodCall(ExprMethodCall {
                        receiver: digest_receiver_chirho,
                        method: digest_method_chirho,
                        args: digest_args_chirho,
                        ..
                    })) if digest_method_chirho == "record_digest_chirho"
                        && digest_args_chirho.is_empty()
                        && path_is_chirho(digest_receiver_chirho, "verified_record_chirho")
                )
                && call_chirho
                    .args
                    .iter()
                    .nth(3)
                    .is_some_and(|bytes_chirho| path_is_chirho(bytes_chirho, "bytes_chirho"));
            self.digest_bound_calls_chirho += usize::from(digest_bound_chirho);
        }
        visit::visit_expr_call(self, call_chirho);
    }
}

#[derive(Default)]
struct Blake3BytesCallVisitorChirho {
    matching_calls_chirho: usize,
}

impl<'ast> Visit<'ast> for Blake3BytesCallVisitorChirho {
    fn visit_expr_call(&mut self, call_chirho: &'ast ExprCall) {
        let is_blake3_hash_chirho = matches!(
            call_chirho.func.as_ref(),
            Expr::Path(path_chirho)
                if path_chirho.path.segments.len() == 2
                    && path_chirho.path.segments[0].ident == "blake3"
                    && path_chirho.path.segments[1].ident == "hash"
        );
        if is_blake3_hash_chirho
            && call_chirho.args.len() == 1
            && call_chirho
                .args
                .first()
                .is_some_and(|bytes_chirho| path_is_chirho(bytes_chirho, "bytes_chirho"))
        {
            self.matching_calls_chirho += 1;
        }
        visit::visit_expr_call(self, call_chirho);
    }
}

struct AddressBindingVisitorChirho<'a> {
    address_ident_chirho: &'a str,
    matching_checks_chirho: usize,
}

impl<'ast> Visit<'ast> for AddressBindingVisitorChirho<'_> {
    fn visit_expr_binary(&mut self, binary_chirho: &'ast ExprBinary) {
        if matches!(binary_chirho.op, BinOp::Ne(_))
            && path_is_chirho(&binary_chirho.right, self.address_ident_chirho)
        {
            let mut hash_chirho = Blake3BytesCallVisitorChirho::default();
            hash_chirho.visit_expr(&binary_chirho.left);
            self.matching_checks_chirho += usize::from(hash_chirho.matching_calls_chirho == 1);
        }
        visit::visit_expr_binary(self, binary_chirho);
    }
}

#[test]
fn move_control_writer_passes_the_verified_record_digest_as_the_address_chirho() {
    let file_chirho = parse_source_chirho(MOVE_CONTROL_STORE_PATH_CHIRHO);
    let function_chirho = function_chirho(
        &file_chirho,
        "store_verified_move_control_record_unlocked_chirho",
    );
    let mut visitor_chirho = DomainWriterCallVisitorChirho::default();
    visitor_chirho.visit_item_fn(function_chirho);
    assert_eq!(
        visitor_chirho.publisher_calls_chirho, 1,
        "the guarded domain writer must have exactly one content-addressed publication call"
    );
    assert_eq!(
        visitor_chirho.digest_bound_calls_chirho, 1,
        "the domain writer must pass verified_record_chirho.record_digest_chirho() as the address and the canonical bytes as the payload"
    );
}

#[test]
fn public_publisher_is_an_exact_delegation_to_the_guarded_inner_function_chirho() {
    let file_chirho = parse_source_chirho(CONTENT_ADDRESSED_NAMESPACE_PATH_CHIRHO);
    let function_chirho = function_chirho(
        &file_chirho,
        "publish_content_addressed_namespace_file_no_replace_chirho",
    );
    assert_eq!(
        function_chirho.block.stmts.len(),
        1,
        "the public publisher must remain a one-expression delegation; an early return or second path would bypass the guarded inner function"
    );
    let Stmt::Expr(Expr::Call(call_chirho), None) = &function_chirho.block.stmts[0] else {
        panic!("the public publisher body must be one tail call to the guarded inner function");
    };
    assert!(
        matches!(
            call_chirho.func.as_ref(),
            Expr::Path(path_chirho)
                if path_chirho
                    .path
                    .segments
                    .last()
                    .is_some_and(|segment_chirho| {
                        segment_chirho.ident
                            == "publish_content_addressed_namespace_file_no_replace_with_injection_chirho"
                    })
        ),
        "the public publisher must delegate to the function whose address check is guarded"
    );
    assert_eq!(
        call_chirho.args.len(),
        6,
        "delegation argument shape changed"
    );
    for (argument_chirho, expected_chirho) in call_chirho.args.iter().take(5).zip([
        "root_chirho",
        "namespace_components_chirho",
        "address_hex_chirho",
        "bytes_chirho",
        "max_bytes_chirho",
    ]) {
        assert!(
            path_is_chirho(argument_chirho, expected_chirho),
            "the public publisher must forward `{expected_chirho}` unchanged"
        );
    }
    assert!(
        matches!(
            call_chirho.args.last(),
        Some(Expr::Call(default_chirho))
            if matches!(
                default_chirho.func.as_ref(),
                Expr::Path(path_chirho)
                    if path_chirho
                        .path
                        .segments
                        .last()
                        .is_some_and(|segment_chirho| segment_chirho.ident == "default")
            )
                && default_chirho.args.is_empty()
        ),
        "normal publication must select the no-injection path"
    );
}

#[test]
fn publisher_and_reader_each_bind_blake3_bytes_to_their_address_chirho() {
    let file_chirho = parse_source_chirho(CONTENT_ADDRESSED_NAMESPACE_PATH_CHIRHO);
    for (function_name_chirho, address_ident_chirho) in [
        (
            "publish_content_addressed_namespace_file_no_replace_with_injection_chirho",
            "address_hex_chirho",
        ),
        ("read_verified_file_at_chirho", "name_chirho"),
    ] {
        let function_chirho = function_chirho(&file_chirho, function_name_chirho);
        let mut visitor_chirho = AddressBindingVisitorChirho {
            address_ident_chirho,
            matching_checks_chirho: 0,
        };
        visitor_chirho.visit_item_fn(function_chirho);
        assert_eq!(
            visitor_chirho.matching_checks_chirho, 1,
            "`{function_name_chirho}` must contain exactly one BLAKE3(bytes) != {address_ident_chirho} refusal; moving or deleting it changes the address invariant and requires review"
        );
    }
}
