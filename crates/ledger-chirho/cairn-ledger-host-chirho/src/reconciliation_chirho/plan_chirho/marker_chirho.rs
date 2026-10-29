// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::contract_chirho::{
    Gd7EffectLineageChirho, Gd7PlanRefusalChirho, Gd7TerminalDispositionChirho,
    Gd7TerminalMarkerChirho, VerifiedGd7TerminalMarkerChirho, GD7_TERMINAL_MARKER_SCHEMA_V1_CHIRHO,
    MAX_GD7_TERMINAL_MARKER_BYTES_CHIRHO,
};
use super::object_chirho::{digest_bytes_chirho, read_bounded_optional_chirho};
use crate::reconciliation_chirho::contract_chirho::{
    is_bounded_label_chirho, is_lower_hex_digest_chirho, MAX_GD7_RECONCILIATION_LABEL_BYTES_CHIRHO,
    MAX_GD7_RECONCILIATION_SIGNATURE_BYTES_CHIRHO,
};
use crate::reconciliation_chirho::{
    Gd7ReconciliationSignerPortChirho, Gd7ReconciliationVerifierPortChirho,
};
use cairn_ledger_log_chirho::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use cairn_ledger_model_chirho::record_chirho::EscrowControlChirho;

const GD7_RECONCILIATION_NAMESPACE_CHIRHO: &str = "gd7-reconciliation-chirho";

pub(super) struct Gd7TerminalMarkerInputChirho<'input_chirho> {
    pub(super) reconciliation_identity_digest_chirho: &'input_chirho str,
    pub(super) intent_ref_chirho: &'input_chirho DigestChirho,
    pub(super) lineage_chirho: Gd7EffectLineageChirho,
    pub(super) original_effect_key_chirho: Option<&'input_chirho str>,
    pub(super) control_chirho: &'input_chirho EscrowControlChirho,
    pub(super) outcome_ref_chirho: &'input_chirho DigestChirho,
    pub(super) disposition_chirho: Gd7TerminalDispositionChirho,
    pub(super) terminal_seq_chirho: u64,
    pub(super) terminal_record_digest_chirho: &'input_chirho str,
}

pub fn gd7_terminal_marker_path_chirho(
    reconciliation_identity_digest_chirho: &str,
    intent_ref_chirho: &DigestChirho,
) -> Result<StoragePathChirho, Gd7PlanRefusalChirho> {
    if !is_lower_hex_digest_chirho(reconciliation_identity_digest_chirho)
        || !is_lower_hex_digest_chirho(&intent_ref_chirho.0)
    {
        return Err(Gd7PlanRefusalChirho::InvalidReferenceChirho);
    }
    Ok(StoragePathChirho::new_chirho(format!(
        "{GD7_RECONCILIATION_NAMESPACE_CHIRHO}/terminal-markers-chirho/{}/{}/{reconciliation_identity_digest_chirho}/{}/{}/{}.json",
        &reconciliation_identity_digest_chirho[..2],
        &reconciliation_identity_digest_chirho[2..4],
        &intent_ref_chirho.0[..2],
        &intent_ref_chirho.0[2..4],
        intent_ref_chirho.0,
    )))
}

pub(crate) fn persist_or_load_terminal_marker_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    input_chirho: Gd7TerminalMarkerInputChirho<'_>,
) -> Result<VerifiedGd7TerminalMarkerChirho, Gd7PlanRefusalChirho> {
    let path_chirho = gd7_terminal_marker_path_chirho(
        input_chirho.reconciliation_identity_digest_chirho,
        input_chirho.intent_ref_chirho,
    )?;
    let expected_unsigned_chirho =
        expected_unsigned_terminal_marker_chirho(signer_chirho, &input_chirho)?;
    if let Some(bytes_chirho) =
        read_terminal_marker_bytes_optional_chirho(storage_chirho, &path_chirho)?
    {
        let verified_chirho = verify_terminal_marker_bytes_chirho(&bytes_chirho, signer_chirho)?;
        ensure_same_marker_chirho(&verified_chirho.marker_chirho, &expected_unsigned_chirho)?;
        return Ok(verified_chirho);
    }

    let mut marker_chirho = expected_unsigned_chirho.clone();
    let unsigned_bytes_chirho = serde_json::to_vec(&marker_chirho)
        .map_err(|_| Gd7PlanRefusalChirho::SerializationChirho)?;
    let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
        .map_err(|_| Gd7PlanRefusalChirho::SerializationChirho)?;
    marker_chirho.sig_chirho = signer_chirho
        .sign_chirho(unsigned_line_chirho)
        .map_err(|_| Gd7PlanRefusalChirho::SigningChirho)?;
    validate_marker_body_chirho(&marker_chirho)?;
    let bytes_chirho = serde_json::to_vec(&marker_chirho)
        .map_err(|_| Gd7PlanRefusalChirho::SerializationChirho)?;
    if bytes_chirho.len() > MAX_GD7_TERMINAL_MARKER_BYTES_CHIRHO {
        return Err(Gd7PlanRefusalChirho::OversizedTerminalMarkerChirho);
    }
    match storage_chirho
        .create_durable_chirho(&path_chirho, &bytes_chirho)
        .map_err(|_| Gd7PlanRefusalChirho::StorageChirho)?
    {
        CreateDurableOutcomeChirho::CreatedChirho => {
            verify_terminal_marker_bytes_chirho(&bytes_chirho, signer_chirho)
        }
        CreateDurableOutcomeChirho::AlreadyExistsChirho => {
            let existing_chirho =
                read_terminal_marker_bytes_optional_chirho(storage_chirho, &path_chirho)?
                    .ok_or(Gd7PlanRefusalChirho::ImmutableCollisionChirho)?;
            let verified_chirho =
                verify_terminal_marker_bytes_chirho(&existing_chirho, signer_chirho)?;
            ensure_same_marker_chirho(&verified_chirho.marker_chirho, &expected_unsigned_chirho)?;
            Ok(verified_chirho)
        }
    }
}

/// VERIFIER ONLY, and that is a capability boundary rather than a tidiness preference. This is on
/// the read-only sealed-plan enumeration chain, which a restore path walks; requiring a signer here
/// would force a caller that provably never signs to hold a signing key. See the module header on
/// [`persist_or_load_terminal_marker_chirho`] for the one function on this file's surface that does
/// legitimately sign.
pub(super) fn load_matching_terminal_marker_required_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    input_chirho: Gd7TerminalMarkerInputChirho<'_>,
) -> Result<VerifiedGd7TerminalMarkerChirho, Gd7PlanRefusalChirho> {
    let path_chirho = gd7_terminal_marker_path_chirho(
        input_chirho.reconciliation_identity_digest_chirho,
        input_chirho.intent_ref_chirho,
    )?;
    let expected_unsigned_chirho =
        expected_unsigned_terminal_marker_chirho(verifier_chirho, &input_chirho)?;
    let bytes_chirho = read_terminal_marker_bytes_optional_chirho(storage_chirho, &path_chirho)?
        .ok_or(Gd7PlanRefusalChirho::MissingTerminalMarkerChirho)?;
    let verified_chirho = verify_terminal_marker_bytes_chirho(&bytes_chirho, verifier_chirho)?;
    ensure_same_marker_chirho(&verified_chirho.marker_chirho, &expected_unsigned_chirho)?;
    Ok(verified_chirho)
}

/// VERIFIER ONLY. Despite the name it never signs — it builds the marker body a signature is
/// EXPECTED to cover, and reads only `key_id_chirho()` off the port.
fn expected_unsigned_terminal_marker_chirho(
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    input_chirho: &Gd7TerminalMarkerInputChirho<'_>,
) -> Result<Gd7TerminalMarkerChirho, Gd7PlanRefusalChirho> {
    let expected_unsigned_chirho = Gd7TerminalMarkerChirho {
        schema_chirho: GD7_TERMINAL_MARKER_SCHEMA_V1_CHIRHO.to_owned(),
        reconciliation_identity_digest_chirho: input_chirho
            .reconciliation_identity_digest_chirho
            .to_owned(),
        intent_ref_chirho: input_chirho.intent_ref_chirho.clone(),
        lineage_chirho: input_chirho.lineage_chirho,
        original_effect_key_chirho: input_chirho.original_effect_key_chirho.map(str::to_owned),
        control_chirho: input_chirho.control_chirho.clone(),
        outcome_ref_chirho: input_chirho.outcome_ref_chirho.clone(),
        disposition_chirho: input_chirho.disposition_chirho,
        terminal_seq_chirho: input_chirho.terminal_seq_chirho,
        terminal_record_digest_chirho: input_chirho.terminal_record_digest_chirho.to_owned(),
        key_id_chirho: verifier_chirho.key_id_chirho(),
        sig_chirho: String::new(),
    };
    validate_marker_body_chirho(&expected_unsigned_chirho)?;
    Ok(expected_unsigned_chirho)
}

/// VERIFIER ONLY. Reached from BOTH marker access modes — it sits outside the access-mode match in
/// the reducer — so it must never demand more authority than the read-only mode can lawfully hold.
pub(crate) fn load_terminal_marker_optional_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    reconciliation_identity_digest_chirho: &str,
    intent_ref_chirho: &DigestChirho,
) -> Result<Option<VerifiedGd7TerminalMarkerChirho>, Gd7PlanRefusalChirho> {
    let path_chirho =
        gd7_terminal_marker_path_chirho(reconciliation_identity_digest_chirho, intent_ref_chirho)?;
    read_terminal_marker_bytes_optional_chirho(storage_chirho, &path_chirho)?
        .map(|bytes_chirho| verify_terminal_marker_bytes_chirho(&bytes_chirho, verifier_chirho))
        .transpose()
}

fn read_terminal_marker_bytes_optional_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
) -> Result<Option<Vec<u8>>, Gd7PlanRefusalChirho> {
    match read_bounded_optional_chirho(
        storage_chirho,
        path_chirho,
        MAX_GD7_TERMINAL_MARKER_BYTES_CHIRHO,
    ) {
        Err(Gd7PlanRefusalChirho::OversizedPlanPageChirho) => {
            Err(Gd7PlanRefusalChirho::OversizedTerminalMarkerChirho)
        }
        result_chirho => result_chirho,
    }
}

/// VERIFIER ONLY — it verifies, which is the whole of its job.
fn verify_terminal_marker_bytes_chirho(
    bytes_chirho: &[u8],
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
) -> Result<VerifiedGd7TerminalMarkerChirho, Gd7PlanRefusalChirho> {
    if bytes_chirho.len() > MAX_GD7_TERMINAL_MARKER_BYTES_CHIRHO {
        return Err(Gd7PlanRefusalChirho::OversizedTerminalMarkerChirho);
    }
    let marker_chirho: Gd7TerminalMarkerChirho = serde_json::from_slice(bytes_chirho)
        .map_err(|_| Gd7PlanRefusalChirho::MalformedTerminalMarkerChirho)?;
    if serde_json::to_vec(&marker_chirho).map_err(|_| Gd7PlanRefusalChirho::SerializationChirho)?
        != bytes_chirho
    {
        return Err(Gd7PlanRefusalChirho::NonCanonicalTerminalMarkerChirho);
    }
    validate_marker_body_chirho(&marker_chirho)?;
    if marker_chirho.key_id_chirho != verifier_chirho.key_id_chirho() {
        return Err(Gd7PlanRefusalChirho::InvalidTerminalMarkerSignatureChirho);
    }
    let mut unsigned_chirho = marker_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    let unsigned_bytes_chirho = serde_json::to_vec(&unsigned_chirho)
        .map_err(|_| Gd7PlanRefusalChirho::SerializationChirho)?;
    let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
        .map_err(|_| Gd7PlanRefusalChirho::SerializationChirho)?;
    if !verifier_chirho.verify_chirho(unsigned_line_chirho, &marker_chirho.sig_chirho) {
        return Err(Gd7PlanRefusalChirho::InvalidTerminalMarkerSignatureChirho);
    }
    Ok(VerifiedGd7TerminalMarkerChirho {
        object_digest_chirho: digest_bytes_chirho(bytes_chirho),
        marker_chirho,
    })
}

fn validate_marker_body_chirho(
    marker_chirho: &Gd7TerminalMarkerChirho,
) -> Result<(), Gd7PlanRefusalChirho> {
    if marker_chirho.schema_chirho != GD7_TERMINAL_MARKER_SCHEMA_V1_CHIRHO
        || !is_lower_hex_digest_chirho(&marker_chirho.reconciliation_identity_digest_chirho)
        || !is_lower_hex_digest_chirho(&marker_chirho.intent_ref_chirho.0)
        || !is_lower_hex_digest_chirho(&marker_chirho.control_chirho.saga_id_chirho.0)
        || !is_lower_hex_digest_chirho(&marker_chirho.outcome_ref_chirho.0)
        || !is_lower_hex_digest_chirho(&marker_chirho.terminal_record_digest_chirho)
        || marker_chirho
            .original_effect_key_chirho
            .as_deref()
            .is_some_and(|key_chirho| {
                !is_bounded_label_chirho(key_chirho, MAX_GD7_RECONCILIATION_LABEL_BYTES_CHIRHO)
            })
        || !is_bounded_label_chirho(
            &marker_chirho.key_id_chirho,
            MAX_GD7_RECONCILIATION_LABEL_BYTES_CHIRHO,
        )
        || (!marker_chirho.sig_chirho.is_empty()
            && !is_bounded_label_chirho(
                &marker_chirho.sig_chirho,
                MAX_GD7_RECONCILIATION_SIGNATURE_BYTES_CHIRHO,
            ))
    {
        return Err(Gd7PlanRefusalChirho::MalformedTerminalMarkerChirho);
    }
    Ok(())
}

fn ensure_same_marker_chirho(
    actual_chirho: &Gd7TerminalMarkerChirho,
    expected_unsigned_chirho: &Gd7TerminalMarkerChirho,
) -> Result<(), Gd7PlanRefusalChirho> {
    let mut actual_unsigned_chirho = actual_chirho.clone();
    actual_unsigned_chirho.sig_chirho.clear();
    if actual_unsigned_chirho != *expected_unsigned_chirho {
        return Err(Gd7PlanRefusalChirho::TerminalMarkerMismatchChirho);
    }
    Ok(())
}
