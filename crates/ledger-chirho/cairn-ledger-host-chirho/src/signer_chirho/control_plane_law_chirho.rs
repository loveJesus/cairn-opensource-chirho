// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Builds a root's control-plane law at startup from its reviewed host config, its geo evidence and,
//! on a voter, its loaded runtime signers, so every control-plane record knows which key it carries.
//!
//! Config decides, and root evidence can only force a refusal (`select_control_plane_law_chirho`).
//! - The role key must be distinct from the GD7 control key and the node's own key. On a voter it must
//!   also be distinct from the six runtime signers, compared through the H3 matching helpers, so no
//!   runtime key bytes leave the signer set.
//! - On a voter the signer seed is resolved read-only and never minted. Off the voter set it is never
//!   resolved at all (decision rule 6).
//! - Everything here reads; nothing writes. The law marker is published later, by the first lineage
//!   signing (brick 1b).
//!
//! Design: `spec-chirho/workstream-state-chirho/c2-durability-chirho/brick1-control-plane-signer-design-chirho.md`
//! (C2.1 brick 1a-iii, section 2a).

use super::{hex_decode_key_chirho, HostLedgerSignersChirho};
use anyhow::{anyhow, bail, Result};
use cairn_config_chirho::config_chirho::LedgerHostConfigChirho;
use cairn_secret_chirho::secret_chirho::{resolve_secret_ref_chirho, secret_ref_chirho};
use cairn_signer_chirho::control_plane_signer_chirho::{
    refuse_control_plane_role_collisions_chirho, select_control_plane_law_chirho,
    ControlPlaneConfigChirho, ControlPlaneLawChirho, ControlPlaneLineageChirho,
    ControlPlanePinChirho, ControlPlaneSeparationPeerChirho, ControlPlaneSignerChirho,
    ControlPlaneVerifierChirho,
};
use cairn_signer_chirho::signer_chirho::existing_pubkey_hex_chirho;
use cairn_tenant_chirho::tenant_chirho::validate_tenant_id_chirho;
use cairn_writer_head_chirho::control_plane_evidence_chirho::read_control_plane_evidence_chirho;
use std::path::Path;
use zeroize::Zeroizing;

/// Where this node stands in the placement. A voter holds the loaded runtime signers, which the role
/// key must stay distinct from; any other node only verifies.
pub enum ControlPlaneSignerScopeChirho<'signers_chirho> {
    VoterChirho(&'signers_chirho HostLedgerSignersChirho),
    VerifierOnlyChirho,
}

/// Choose this root's control-plane law.
///
/// With no host config, or a config with no control-plane block, the root keeps its node key unless it
/// shows geo evidence, which refuses. A block selects the lineage law once its tenant, the pin's
/// separation and, on a voter, its signer have been checked.
pub fn configured_control_plane_law_chirho(
    root_chirho: &Path,
    config_chirho: Option<&LedgerHostConfigChirho>,
    scope_chirho: ControlPlaneSignerScopeChirho<'_>,
    runtime_tenant_chirho: Option<&str>,
    selected_control_key_hex_chirho: &str,
) -> Result<ControlPlaneLawChirho> {
    let evidence_chirho = read_control_plane_evidence_chirho(root_chirho)?;
    let block_chirho = match config_chirho {
        Some(config_chirho) => {
            config_chirho.validate_chirho()?;
            config_chirho.control_plane_chirho.as_ref()
        }
        None => None,
    };
    let Some(block_chirho) = block_chirho else {
        return Ok(select_control_plane_law_chirho(None, &evidence_chirho)?);
    };
    // The lineage names the tenant this runtime serves, by cairn-tenant's own rule (agy #29556).
    validate_tenant_id_chirho(&block_chirho.tenant_id_chirho)
        .map_err(|_error_chirho| anyhow!("ControlPlaneTenantInvalidChirho"))?;
    if runtime_tenant_chirho != Some(block_chirho.tenant_id_chirho.as_str()) {
        bail!("ControlPlaneTenantMismatchChirho");
    }
    let verifier_chirho = ControlPlaneVerifierChirho::new_chirho(
        ControlPlanePinChirho::from_hex_chirho(&block_chirho.verifying_key_hex_chirho)?,
        ControlPlaneLineageChirho::new_chirho(
            &block_chirho.tenant_id_chirho,
            &block_chirho.genesis_instance_id_chirho,
        )?,
    );
    let node_key_hex_chirho = existing_pubkey_hex_chirho(root_chirho)
        .map_err(|_error_chirho| anyhow!("ControlPlaneNodeKeyUnavailableChirho"))?;
    refuse_control_plane_role_collisions_chirho(
        verifier_chirho.pin_chirho(),
        block_chirho.signer_secret_chirho.as_deref(),
        &[
            key_peer_chirho("gd7-control-key-chirho", selected_control_key_hex_chirho)?,
            key_peer_chirho("node-key-chirho", &node_key_hex_chirho)?,
        ],
    )?;
    let signer_chirho = match scope_chirho {
        ControlPlaneSignerScopeChirho::VerifierOnlyChirho => None,
        ControlPlaneSignerScopeChirho::VoterChirho(signers_chirho) => Some(voter_signer_chirho(
            root_chirho,
            block_chirho.signer_secret_chirho.as_deref(),
            signers_chirho,
            &verifier_chirho,
        )?),
    };
    Ok(select_control_plane_law_chirho(
        Some(ControlPlaneConfigChirho::new_chirho(
            verifier_chirho,
            signer_chirho,
        )?),
        &evidence_chirho,
    )?)
}

/// Load a voter's role signer. Its secret must be named, distinct by name and key from the six runtime
/// signers, resolved read-only, exactly 32 bytes, and for exactly this pin. Separation is checked before
/// the secret is read.
fn voter_signer_chirho(
    root_chirho: &Path,
    secret_name_chirho: Option<&str>,
    signers_chirho: &HostLedgerSignersChirho,
    verifier_chirho: &ControlPlaneVerifierChirho,
) -> Result<ControlPlaneSignerChirho> {
    let secret_name_chirho =
        secret_name_chirho.ok_or_else(|| anyhow!("ControlPlaneVoterSignerMissingChirho"))?;
    if let Some(role_chirho) = signers_chirho.matching_secret_name_role_chirho(secret_name_chirho) {
        bail!("ControlPlaneRoleSecretNameCollisionChirho: {role_chirho:?}");
    }
    if let Some(role_chirho) = signers_chirho
        .matching_verifying_identity_role_chirho(&verifier_chirho.pin_chirho().key_bytes_chirho())
    {
        bail!("ControlPlaneRoleKeyCollisionChirho: {role_chirho:?}");
    }
    let secret_ref_chirho = secret_ref_chirho(secret_name_chirho)
        .map_err(|_error_chirho| anyhow!("ControlPlaneSignerSecretNameInvalidChirho"))?;
    let secret_value_chirho = resolve_secret_ref_chirho(root_chirho, &secret_ref_chirho)
        .map_err(|_error_chirho| anyhow!("ControlPlaneSignerSecretUnavailableChirho"))?;
    if secret_value_chirho.as_bytes_chirho().len() != 32 {
        bail!("ControlPlaneSignerSecretLengthChirho");
    }
    let mut seed_chirho = Zeroizing::new([0_u8; 32]);
    seed_chirho.copy_from_slice(secret_value_chirho.as_bytes_chirho());
    ControlPlaneSignerChirho::from_seed_chirho(seed_chirho, verifier_chirho.clone())
}

/// A separation peer known only by its public key.
fn key_peer_chirho(
    label_chirho: &str,
    key_hex_chirho: &str,
) -> Result<ControlPlaneSeparationPeerChirho> {
    let key_chirho = hex_decode_key_chirho(key_hex_chirho)
        .ok_or_else(|| anyhow!("ControlPlanePeerKeyInvalidChirho: {label_chirho}"))?;
    Ok(ControlPlaneSeparationPeerChirho {
        label_chirho: label_chirho.to_owned(),
        secret_name_chirho: None,
        key_chirho: Some(key_chirho),
    })
}

#[cfg(test)]
#[path = "control_plane_law_chirho/tests_chirho.rs"]
mod tests_chirho;
