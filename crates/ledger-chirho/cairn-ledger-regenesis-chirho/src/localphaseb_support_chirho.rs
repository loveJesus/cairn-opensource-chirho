// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The SOLE production packet→cut evidence entry for the credits-demo LocalPhaseB smoke (#6050
//! HOLD A closure): it takes the canonical H3 packet BYTES plus the regenesis receipt's expected
//! packet digest, re-digests and canonically parses them, exact-selects the ONE balance projection
//! evidence row by name, binds the row's source family to the packet's source-privacy family, forms
//! the read-model cut claim INTERNALLY, and invokes the low receipt/walk verifier — so a PASS
//! packet can never be built from a caller-formed claim naming a different row/family than the
//! canonical packet selected.
//!
//! Workflow: `spec-chirho/workflows-chirho/reversible-postgres-effect-chirho/credits-demo-localphaseb-smoke-chirho.md`.

use crate::completion_chirho::{
    ledger_regenesis_evidence_packet_digest_chirho,
    parse_canonical_ledger_regenesis_evidence_packet_chirho,
};
use anyhow::{bail, Result};
use cairn_ledger_log_chirho::ports_chirho::StoragePathChirho;
use cairn_ledger_model_chirho::record_chirho::HlcChirho;
use cairn_ledger_read_model_chirho::localphaseb_evidence_chirho::{
    H3RegenesisCutPacketClaimChirho, LocalPhaseBEvidencePortsChirho,
    VerifiedLocalPhaseBEvidenceChirho,
};
use cairn_ledger_read_model_chirho::serving_chirho::journal_source_family_id_chirho;

/// Packet-provenance-sealed LocalPhaseB evidence: the receipt-verified cut/census object PLUS the
/// packet-scoped source-family provenance and the packet digest. Family is packet-internal
/// (receipts do not carry it), so it lives HERE — verified against the packet's source-privacy
/// evidence — never as a copied field inside the receipt-verified low object. Fields are PRIVATE;
/// [`verified_localphaseb_evidence_from_packet_chirho`] is the sole producer.
pub struct LocalPhaseBPacketEvidenceChirho {
    source_family_id_chirho: String,
    packet_digest_chirho: String,
    evidence_chirho: VerifiedLocalPhaseBEvidenceChirho,
}

impl LocalPhaseBPacketEvidenceChirho {
    pub fn source_family_id_chirho(&self) -> &str {
        &self.source_family_id_chirho
    }
    pub fn packet_digest_chirho(&self) -> &str {
        &self.packet_digest_chirho
    }
    pub fn evidence_chirho(&self) -> &VerifiedLocalPhaseBEvidenceChirho {
        &self.evidence_chirho
    }
}

/// Build the packet-provenance-sealed LocalPhaseB evidence. Law order: (1) the packet BYTES must
/// re-digest to the regenesis receipt's recorded packet digest (equality, never non-empty); (2)
/// exact-byte canonical parse; (3) exact-select the ONE balance projection evidence row by name —
/// missing or duplicate REFUSES; (4) the row's source family must equal the packet source-privacy
/// family; (5) the cut claim is formed HERE from the selected row and handed to the low
/// receipt/walk verifier, which verifies-or-refuses every coordinate against the signed pre-L2
/// head, the final head, and the live verified chain.
pub fn verified_localphaseb_evidence_from_packet_chirho(
    packet_bytes_chirho: &[u8],
    expected_packet_digest_chirho: &str,
    balance_projection_name_chirho: &str,
    ports_chirho: LocalPhaseBEvidencePortsChirho<'_>,
    regenesis_head_path_chirho: &StoragePathChirho,
) -> Result<LocalPhaseBPacketEvidenceChirho> {
    if expected_packet_digest_chirho.is_empty() {
        bail!("expected H3 packet digest is empty (the regenesis receipt digest is required)");
    }
    let packet_digest_chirho = ledger_regenesis_evidence_packet_digest_chirho(packet_bytes_chirho);
    if packet_digest_chirho != expected_packet_digest_chirho {
        bail!("H3 packet bytes re-digest does not equal the regenesis receipt packet digest");
    }
    let packet_chirho =
        parse_canonical_ledger_regenesis_evidence_packet_chirho(packet_bytes_chirho).map_err(
            |error_chirho| anyhow::anyhow!("H3 packet canonical parse refused: {error_chirho:?}"),
        )?;

    let mut balance_rows_chirho = packet_chirho
        .projections_chirho
        .iter()
        .filter(|row_chirho| row_chirho.projection_name_chirho == balance_projection_name_chirho);
    let row_chirho = balance_rows_chirho.next().ok_or_else(|| {
        anyhow::anyhow!(
            "H3 packet has no projection evidence named '{balance_projection_name_chirho}'"
        )
    })?;
    if balance_rows_chirho.next().is_some() {
        bail!(
            "H3 packet has duplicate projection evidence named '{balance_projection_name_chirho}'"
        );
    }
    if row_chirho.source_family_id_chirho != packet_chirho.source_privacy_chirho.family_id_chirho {
        bail!(
            "H3 packet balance projection source family does not equal the packet source-privacy \
             family"
        );
    }
    // The DERIVED family bind (#6051): the packet's asserted family must equal the pure function
    // of the receipt/chain-bound cluster id — the packet cannot name a foreign source family.
    let derived_family_chirho =
        journal_source_family_id_chirho(ports_chirho.source_chirho.cluster_chirho);
    if row_chirho.source_family_id_chirho != derived_family_chirho {
        bail!(
            "H3 packet source family does not equal the journal source family derived from the \
             bound cluster"
        );
    }

    let claim_chirho = H3RegenesisCutPacketClaimChirho {
        projection_name_chirho: row_chirho.projection_name_chirho.clone(),
        descriptor_digest_chirho: row_chirho.descriptor_digest_chirho.clone(),
        source_seq_chirho: row_chirho.source_seq_chirho,
        source_hlc_chirho: HlcChirho {
            physical_ms_chirho: row_chirho.source_hlc_physical_ms_chirho,
            logical_chirho: row_chirho.source_hlc_logical_chirho,
        },
        signed_prefix_digest_chirho: row_chirho.signed_prefix_digest_chirho.clone(),
        view_digest_hex_chirho: row_chirho.view_digest_chirho.0.clone(),
        account_owner_chirho: row_chirho.account_chirho.owner_chirho.clone(),
        account_kind_chirho: row_chirho.account_chirho.kind_id_chirho.0.clone(),
        account_net_chirho: row_chirho.account_net_chirho,
    };
    let evidence_chirho = VerifiedLocalPhaseBEvidenceChirho::verify_and_bind_chirho(
        ports_chirho,
        &claim_chirho,
        regenesis_head_path_chirho,
    )?;
    Ok(LocalPhaseBPacketEvidenceChirho {
        source_family_id_chirho: row_chirho.source_family_id_chirho.clone(),
        packet_digest_chirho,
        evidence_chirho,
    })
}
