// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Gives the two shipped raw-body absence claims default-gate reach.
//!
//! The behavioral wiring arms in `cas_absence_evidence_chirho/wiring_tests_chirho.rs` prove that
//! genuine absence may pass while tampered and unreadable objects refuse. The contact arm cannot run
//! in the default gate because its real entrypoint builds the wasm32 guest first. This narrow source
//! guard complements those arms: it keeps exactly the two shipped boolean bindings on the reviewed
//! fail-closed helper during every default source-scan run. It does not replace the behavioral proof.
//!
//! REVIEWED BOUNDARY - all eight independently planted shapes are named here so green is not read as
//! more than this textual guard proves:
//!
//! 1. Caught, LITERALLY AND ONLY: replacing this call's own `)?;` with `.unwrap_or(true)` breaks the
//!    full-call needle. Read this narrowly - it does NOT mean "an unwrap_or(true) swallow is caught".
//!    See shape 9.
//! 2. Not caught: an aliased or redirected import can preserve byte-identical call text.
//! 3. Not caught: a later shadowing rebind can replace the checked local.
//! 4. Not caught: the shipped report field can be rewired while the checked `let` remains.
//! 5. Caught for line-leading `//` comments: `production_source_lines_chirho` excludes them before
//!    matching. This is not a claim about every block- or inline-comment trick.
//! 6. Not caught: a `#[cfg(feature)]` alternate binding can coexist with the checked source.
//! 7. Caught: the full-call needle deliberately pins the reviewed arguments and their order.
//! 8. Not caught: this is a two-file allowlist, not a census for a third production absence claim.
//! 9. NOT CAUGHT, and it is shape 1 moved one syntactic level out: an ENCLOSING expression - a closure,
//!    a `match`, a method chain - can swallow the fallible call while the reviewed needle survives
//!    BYTE-INTACT and the helper-call count stays at one. Measured by an independent reviewer: it
//!    compiles, the guard stays GREEN, and every Unreadable/Tampered refusal becomes "absent = true" -
//!    the exact defect this file exists to prevent. Blast radius measured and asymmetric: at the
//!    AGENT site the behavioural wiring arm runs by default and catches it; at the CONTACT site - the
//!    very site this guard exists for, because its arm needs the operator-smoke feature - there is NO
//!    default-gate backstop for this shape.

use super::super::*;

const ABSENCE_HELPER_CHIRHO: &str = "raw_body_absent_from_public_cas_chirho";
const ABSENCE_HELPER_SOURCE_CHIRHO: &str =
    "crates/services-chirho/cairn-operator-smoke-chirho/src/cas_absence_evidence_chirho.rs";

const SHIPPING_ABSENCE_CALLS_CHIRHO: &[(&str, &str)] = &[
    (
        "crates/services-chirho/cairn-operator-smoke-chirho/src/contact_example_smoke_chirho.rs",
        "let raw_body_absent_from_cas_chirho = raw_body_absent_from_public_cas_chirho( \
         root_chirho, &raw_hash_chirho, \"contact example raw body\", )?;",
    ),
    (
        "crates/services-chirho/cairn-operator-smoke-chirho/src/agent_authored_backend_smoke_chirho.rs",
        "let missing_policy_raw_body_absent_from_cas_chirho = \
         raw_body_absent_from_public_cas_chirho( root_chirho, &safe_body_hash_chirho, \
         \"agent-authored backend pre-policy body\", )?;",
    ),
];

fn normalized_file_production_source_chirho(
    production_lines_chirho: &[(String, usize, String)],
    path_chirho: &str,
) -> String {
    production_lines_chirho
        .iter()
        .filter(|(source_path_chirho, _line_chirho, _text_chirho)| {
            source_path_chirho == path_chirho
        })
        .map(|(_source_path_chirho, _line_chirho, text_chirho)| text_chirho.as_str())
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn shipped_raw_body_absence_claims_stay_on_fail_closed_helper_chirho() {
    let production_lines_chirho = production_source_lines_chirho();
    let helper_production_chirho = normalized_file_production_source_chirho(
        &production_lines_chirho,
        ABSENCE_HELPER_SOURCE_CHIRHO,
    );
    let helper_definition_chirho = format!("fn {ABSENCE_HELPER_CHIRHO}(");

    // Positive control: if the scanner or symbol drifts, both caller checks below could report a
    // misleading zero. The same instrument must first see the one reviewed helper definition.
    assert_eq!(
        helper_production_chirho
            .matches(&helper_definition_chirho)
            .count(),
        1,
        "positive control failed: expected exactly one {ABSENCE_HELPER_CHIRHO} definition in \
         {ABSENCE_HELPER_SOURCE_CHIRHO}"
    );

    for (path_chirho, full_call_chirho) in SHIPPING_ABSENCE_CALLS_CHIRHO {
        let production_chirho =
            normalized_file_production_source_chirho(&production_lines_chirho, path_chirho);
        let call_chirho = format!("{ABSENCE_HELPER_CHIRHO}(");

        assert_eq!(
            production_chirho.matches(&call_chirho).count(),
            1,
            "{path_chirho} must contain exactly one call to {ABSENCE_HELPER_CHIRHO}; the behavioral \
             arms prove its semantics, while this guard keeps that shipped call reachable from the \
             default gate"
        );
        assert_eq!(
            production_chirho.matches(full_call_chirho).count(),
            1,
            "{path_chirho} no longer carries the exact reviewed fallible absence-helper call. The \
             full needle deliberately pins the arguments and `?` propagation: do not swallow an \
             unreadable/tampered refusal, retarget the evidence address, or reorder the reviewed \
             inputs. The module header names what this textual guard still cannot prove."
        );
    }
}
