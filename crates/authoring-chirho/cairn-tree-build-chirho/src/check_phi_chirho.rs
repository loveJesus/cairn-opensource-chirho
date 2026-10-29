// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The phi-role checks: a `builtin-phi-chirho.toml` role must be a well-formed merge point — a
//! strict card, at least two inputs, exactly one output, every input the output's type, and every
//! input a wire from another role — so the engine's exactly-one-live rule can hold at run time.

use crate::check_chirho::{finding_chirho, FindingChirho};
use crate::tree_chirho::{
    PhiBindingChirho, PortChirho, PortSchemaChirho, PortSourceChirho, RoleChirho,
    PHI_CARD_SCHEMA_CHIRHO,
};

/// How two typed ports compare under the same rule wires use: schema hashes when either side
/// declares a schema file, bare type names otherwise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PortAgreementChirho {
    AgreeChirho,
    SchemaMismatchChirho,
    TypeMismatchChirho,
}

pub(crate) fn port_agreement_chirho(
    left_schema_chirho: &PortSchemaChirho,
    left_type_chirho: &str,
    right_schema_chirho: &PortSchemaChirho,
    right_type_chirho: &str,
) -> PortAgreementChirho {
    if left_schema_chirho.declared_chirho || right_schema_chirho.declared_chirho {
        if left_schema_chirho.hash_chirho != right_schema_chirho.hash_chirho {
            return PortAgreementChirho::SchemaMismatchChirho;
        }
    } else if left_type_chirho != right_type_chirho {
        return PortAgreementChirho::TypeMismatchChirho;
    }
    PortAgreementChirho::AgreeChirho
}

fn validate_phi_card_chirho(binding_chirho: &PhiBindingChirho) -> Result<(), String> {
    if let Some(error_chirho) = &binding_chirho.parse_error_chirho {
        return Err(error_chirho.clone());
    }
    if binding_chirho.schema_chirho != PHI_CARD_SCHEMA_CHIRHO {
        return Err(format!(
            "schema_chirho must be {PHI_CARD_SCHEMA_CHIRHO}, found '{}'",
            binding_chirho.schema_chirho
        ));
    }
    if binding_chirho.intent_chirho.trim().is_empty() {
        return Err("intent_chirho must be non-empty".to_string());
    }
    Ok(())
}

/// Is this in-port fed by a wire whose target lives in another ROLE's dir (not the surface, not a
/// pin)? The executor feeds the request only to nodes with no incoming edge, so a surface-fed phi
/// port would silently never arrive; a pin is always live and would collide with the live branch.
fn wired_from_a_role_chirho(port_chirho: &PortChirho) -> bool {
    match &port_chirho.source_chirho {
        Some(PortSourceChirho::WireChirho { target_chirho }) => target_chirho
            .parent()
            .and_then(|parent_chirho| parent_chirho.file_name())
            .and_then(|name_chirho| name_chirho.to_str())
            .map(|name_chirho| name_chirho != "surface_chirho")
            .unwrap_or(false),
        _ => false,
    }
}

/// Part of `spec-chirho/workflows-chirho/tree-build-phi-role-chirho.md`.
pub(crate) fn check_phi_role_chirho(
    role_label_chirho: &str,
    role_chirho: &RoleChirho,
    binding_chirho: &PhiBindingChirho,
    findings_chirho: &mut Vec<FindingChirho>,
) {
    if let Err(reason_chirho) = validate_phi_card_chirho(binding_chirho) {
        findings_chirho.push(finding_chirho(
            "phi-card-invalid-chirho",
            role_label_chirho,
            "this phi role's card is not a strict builtin-phi-v1 document",
            "builtin-phi-chirho.toml with schema_chirho = builtin-phi-v1-chirho and a non-empty intent_chirho",
            &reason_chirho,
            "fix builtin-phi-chirho.toml; it carries only schema_chirho and intent_chirho",
        ));
        return;
    }
    if role_chirho.in_ports_chirho.len() < 2 {
        findings_chirho.push(finding_chirho(
            "phi-inputs-too-few-chirho",
            role_label_chirho,
            "a phi merges branches, so it needs at least two input ports",
            "two or more in- connections, each wired from a different branch's output",
            &format!("{} in- connection(s)", role_chirho.in_ports_chirho.len()),
            "add an in-<name>-<type>-chirho wire per branch; a one-input phi is just a wire",
        ));
    }
    if role_chirho.out_ports_chirho.len() != 1 {
        findings_chirho.push(finding_chirho(
            "phi-output-count-chirho",
            role_label_chirho,
            "a phi passes exactly one live input through, so it has exactly one output port",
            "exactly one out- connection",
            &format!("{} out- connection(s)", role_chirho.out_ports_chirho.len()),
            "keep one out-<name>-<type>-chirho dir; its <name> becomes the engine output port",
        ));
    }
    for port_chirho in &role_chirho.in_ports_chirho {
        let port_label_chirho = format!("{role_label_chirho}/{}", port_chirho.raw_name_chirho);
        // An unsatisfied port is already `port-unsatisfied-chirho` from the generic check.
        if port_chirho.source_chirho.is_some() && !wired_from_a_role_chirho(port_chirho) {
            findings_chirho.push(finding_chirho(
                "phi-input-not-a-role-wire-chirho",
                &port_label_chirho,
                "a phi input must be a wire from another role's output",
                "a symlink to a role's out- connection dir (not the surface, not a pin)",
                match &port_chirho.source_chirho {
                    Some(PortSourceChirho::PinChirho { .. }) => "a pinned content dir",
                    _ => "a wire from the dag surface",
                },
                "wire each phi input from the branch role that produces it; the surface request enters through the branch roles",
            ));
        }
        if let [out_port_chirho] = role_chirho.out_ports_chirho.as_slice() {
            let agreement_chirho = port_agreement_chirho(
                &port_chirho.schema_chirho,
                &port_chirho.parsed_chirho.type_name_chirho,
                &out_port_chirho.schema_chirho,
                &out_port_chirho.parsed_chirho.type_name_chirho,
            );
            if agreement_chirho != PortAgreementChirho::AgreeChirho {
                findings_chirho.push(finding_chirho(
                    "phi-port-type-mismatch-chirho",
                    &port_label_chirho,
                    "every phi input must carry the same type as the phi output, because whichever branch is live passes through unchanged",
                    &format!(
                        "type {} (the out- connection's type)",
                        out_port_chirho.parsed_chirho.type_name_chirho
                    ),
                    &port_chirho.parsed_chirho.type_name_chirho,
                    "rename the in- connection to the output's type, or convert inside the branch role",
                ));
            }
        }
    }
}

#[cfg(test)]
#[path = "check_phi_tests_chirho.rs"]
mod tests_chirho;
