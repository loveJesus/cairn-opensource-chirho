// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The leader-signed custody frame that carries one wrapped key to one holder, and the holder's three gates before it opens it.
//!
//! A holder decodes and authenticates the frame (digest binds every field, the sender's node key
//! signed it), then authorizes it with the MIRROR's own authority check over the holder's own joined
//! view: the exact view and group, holder and sender both serving holders, the stale-term guard, the
//! sender-is-the-current-leader inversion, and the leader's rebased lease. It then checks its erasure
//! tombstones, so a frame delayed past an erasure cannot bring a key back. Only an
//! `AuthorizedCustodyFrameChirho` can open the wrapped key, so no step can be skipped.

use crate::custody_chirho::binding_chirho::CustodyBindingChirho;
use crate::custody_chirho::wrap_chirho::{
    open_wrapped_key_chirho, ShredKeyRecordChirho, WrappedKeyPayloadChirho,
};
use crate::custody_key_chirho::NodeCustodySecretChirho;
use crate::digest_chirho::{
    decode_hex_32_chirho, update_digest_field_chirho, update_lease_field_chirho,
    valid_lower_hex_chirho, validate_signature_hex_chirho, verify_node_signature_chirho,
    DIGEST_HEX_BYTES_CHIRHO,
};
use crate::erasure_chirho::tombstone_chirho::HolderTombstonesChirho;
use crate::refusal_chirho::{
    refuse_chirho, KeyCustodyErrorChirho, KeyCustodyRefusalIdentityChirho,
};
use cairn_mirror_chirho::{
    verify_mirror_authority_binding_chirho, JoinedMirrorViewChirho, MirrorAuthorityFrameViewChirho,
};
use cairn_writer_elector_chirho::monotonic_clock_chirho::MonotonicClockChirho;
use serde::{Deserialize, Serialize};
use std::num::NonZeroU64;

pub const CUSTODY_FRAME_SCHEMA_V1_CHIRHO: &str = "key-custody-frame-v1-chirho";
/// A custody frame carries one small wrapped record; anything larger is refused before parsing.
pub const KEY_CUSTODY_WIRE_MAX_BYTES_CHIRHO: usize = 16 * 1024;
const CUSTODY_FRAME_DIGEST_DOMAIN_V1_CHIRHO: &[u8] = b"cairn-key-custody-frame-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyFrameV1Chirho {
    schema_chirho: String,
    binding_chirho: CustodyBindingChirho,
    leader_lease_remaining_millis_chirho: Option<u64>,
    wrapped_key_chirho: WrappedKeyPayloadChirho,
    frame_digest_chirho: String,
    sig_hex_chirho: String,
}

/// A frame whose fields are validated and whose digest is computed, not yet signed. Production signs
/// `signing_digest_chirho` through the node signer.
pub struct PreparedCustodyFrameChirho {
    frame_chirho: CustodyFrameV1Chirho,
}

impl PreparedCustodyFrameChirho {
    pub fn new_chirho(
        binding_chirho: CustodyBindingChirho,
        leader_lease_remaining_millis_chirho: Option<u64>,
        wrapped_key_chirho: WrappedKeyPayloadChirho,
    ) -> Result<Self, KeyCustodyErrorChirho> {
        let mut frame_chirho = CustodyFrameV1Chirho {
            schema_chirho: CUSTODY_FRAME_SCHEMA_V1_CHIRHO.to_string(),
            binding_chirho,
            leader_lease_remaining_millis_chirho,
            wrapped_key_chirho,
            frame_digest_chirho: String::new(),
            sig_hex_chirho: String::new(),
        };
        validate_frame_semantics_chirho(&frame_chirho)?;
        frame_chirho.frame_digest_chirho = frame_digest_hex_chirho(&frame_chirho);
        Ok(Self { frame_chirho })
    }

    pub fn signing_digest_chirho(&self) -> [u8; 32] {
        decode_hex_32_chirho(&self.frame_chirho.frame_digest_chirho)
            .expect("a prepared custody frame always carries a validated digest")
    }

    pub fn into_signed_chirho(
        mut self,
        sig_hex_chirho: String,
    ) -> Result<CustodyFrameV1Chirho, KeyCustodyErrorChirho> {
        validate_signature_hex_chirho(
            &sig_hex_chirho,
            KeyCustodyRefusalIdentityChirho::CustodyFrameInvalidChirho,
        )?;
        self.frame_chirho.sig_hex_chirho = sig_hex_chirho;
        Ok(self.frame_chirho)
    }
}

impl CustodyFrameV1Chirho {
    pub fn to_wire_bytes_chirho(&self) -> Result<Vec<u8>, KeyCustodyErrorChirho> {
        let bytes_chirho = serde_json::to_vec(self).map_err(|_| wire_invalid_chirho())?;
        if bytes_chirho.len() > KEY_CUSTODY_WIRE_MAX_BYTES_CHIRHO {
            return Err(wire_invalid_chirho());
        }
        Ok(bytes_chirho)
    }

    pub fn frame_digest_chirho(&self) -> &str {
        &self.frame_digest_chirho
    }

    pub fn binding_chirho(&self) -> &CustodyBindingChirho {
        &self.binding_chirho
    }
}

/// A frame whose digest binds its fields and whose sender's node key signed it. Not yet authorized.
#[derive(Debug)]
pub struct AuthenticatedCustodyFrameChirho {
    frame_chirho: CustodyFrameV1Chirho,
}

impl AuthenticatedCustodyFrameChirho {
    pub fn binding_chirho(&self) -> &CustodyBindingChirho {
        &self.frame_chirho.binding_chirho
    }
}

impl MirrorAuthorityFrameViewChirho for AuthenticatedCustodyFrameChirho {
    fn origin_node_id_chirho(&self) -> &str {
        &self.frame_chirho.binding_chirho.origin_node_id_chirho
    }

    fn target_node_id_chirho(&self) -> &str {
        &self.frame_chirho.binding_chirho.holder_node_id_chirho
    }

    fn consistency_group_digest_chirho(&self) -> &str {
        &self
            .frame_chirho
            .binding_chirho
            .consistency_group_digest_chirho
    }

    fn membership_view_digest_chirho(&self) -> &str {
        &self
            .frame_chirho
            .binding_chirho
            .membership_view_digest_chirho
    }

    fn expected_term_chirho(&self) -> u64 {
        self.frame_chirho.binding_chirho.elected_term_chirho
    }

    fn leader_lease_remaining_millis_chirho(&self) -> Option<u64> {
        self.frame_chirho.leader_lease_remaining_millis_chirho
    }
}

pub fn decode_and_authenticate_custody_frame_chirho(
    wire_bytes_chirho: &[u8],
) -> Result<AuthenticatedCustodyFrameChirho, KeyCustodyErrorChirho> {
    if wire_bytes_chirho.len() > KEY_CUSTODY_WIRE_MAX_BYTES_CHIRHO {
        return Err(wire_invalid_chirho());
    }
    let frame_chirho: CustodyFrameV1Chirho =
        serde_json::from_slice(wire_bytes_chirho).map_err(|_| wire_invalid_chirho())?;
    validate_frame_semantics_chirho(&frame_chirho)?;
    if frame_chirho.frame_digest_chirho != frame_digest_hex_chirho(&frame_chirho) {
        return Err(refuse_chirho(
            KeyCustodyRefusalIdentityChirho::CustodyFrameInvalidChirho,
            "the frame digest does not bind its fields",
        ));
    }
    let digest_chirho =
        decode_hex_32_chirho(&frame_chirho.frame_digest_chirho).ok_or_else(|| {
            refuse_chirho(
                KeyCustodyRefusalIdentityChirho::CustodyFrameInvalidChirho,
                "the frame digest is not 32 bytes",
            )
        })?;
    verify_node_signature_chirho(
        &frame_chirho.binding_chirho.origin_node_id_chirho,
        &digest_chirho,
        &frame_chirho.sig_hex_chirho,
        KeyCustodyRefusalIdentityChirho::CustodyFrameInvalidChirho,
    )?;
    Ok(AuthenticatedCustodyFrameChirho { frame_chirho })
}

/// A frame this holder may open: its sender is the current leader of this holder's exact joined view,
/// and no erasure tombstone on this holder covers its key.
#[derive(Debug)]
pub struct AuthorizedCustodyFrameChirho {
    frame_chirho: CustodyFrameV1Chirho,
}

/// Authorize with the mirror's own check, then the holder's tombstones. `receiver_node_id_chirho` is
/// THIS holder and `joined_chirho` is ITS OWN joined view; neither comes from the frame.
pub fn authorize_custody_frame_chirho(
    authenticated_chirho: AuthenticatedCustodyFrameChirho,
    joined_chirho: &JoinedMirrorViewChirho,
    receiver_node_id_chirho: &str,
    tombstones_chirho: &HolderTombstonesChirho,
    clock_chirho: &dyn MonotonicClockChirho,
    transit_budget_millis_chirho: NonZeroU64,
) -> Result<AuthorizedCustodyFrameChirho, KeyCustodyErrorChirho> {
    verify_mirror_authority_binding_chirho(
        &authenticated_chirho,
        joined_chirho,
        receiver_node_id_chirho,
        clock_chirho,
        transit_budget_millis_chirho,
    )
    .map_err(KeyCustodyErrorChirho::from_mirror_authority_chirho)?;
    tombstones_chirho.check_custody_binding_chirho(authenticated_chirho.binding_chirho())?;
    Ok(AuthorizedCustodyFrameChirho {
        frame_chirho: authenticated_chirho.frame_chirho,
    })
}

impl AuthorizedCustodyFrameChirho {
    pub fn binding_chirho(&self) -> &CustodyBindingChirho {
        &self.frame_chirho.binding_chirho
    }

    pub fn frame_digest_chirho(&self) -> &str {
        &self.frame_chirho.frame_digest_chirho
    }

    /// Open the wrapped key with this holder's custody secret.
    pub fn open_chirho(
        &self,
        holder_secret_chirho: &NodeCustodySecretChirho,
    ) -> Result<OpenedCustodyKeyChirho, KeyCustodyErrorChirho> {
        let record_chirho = open_wrapped_key_chirho(
            &self.frame_chirho.wrapped_key_chirho,
            holder_secret_chirho,
            &self.frame_chirho.binding_chirho,
        )?;
        Ok(OpenedCustodyKeyChirho {
            binding_chirho: self.frame_chirho.binding_chirho.clone(),
            frame_digest_chirho: self.frame_chirho.frame_digest_chirho.clone(),
            record_chirho,
        })
    }
}

/// An opened key: its binding, the frame that carried it, and the record to store durably.
#[derive(Debug)]
pub struct OpenedCustodyKeyChirho {
    binding_chirho: CustodyBindingChirho,
    frame_digest_chirho: String,
    record_chirho: ShredKeyRecordChirho,
}

impl OpenedCustodyKeyChirho {
    pub fn binding_chirho(&self) -> &CustodyBindingChirho {
        &self.binding_chirho
    }

    pub fn frame_digest_chirho(&self) -> &str {
        &self.frame_digest_chirho
    }

    pub fn record_chirho(&self) -> &ShredKeyRecordChirho {
        &self.record_chirho
    }
}

fn validate_frame_semantics_chirho(
    frame_chirho: &CustodyFrameV1Chirho,
) -> Result<(), KeyCustodyErrorChirho> {
    if frame_chirho.schema_chirho != CUSTODY_FRAME_SCHEMA_V1_CHIRHO {
        return Err(refuse_chirho(
            KeyCustodyRefusalIdentityChirho::CustodyFrameInvalidChirho,
            "the frame schema is unsupported",
        ));
    }
    frame_chirho.binding_chirho.validate_chirho()?;
    if !frame_chirho.wrapped_key_chirho.in_form_chirho() {
        return Err(refuse_chirho(
            KeyCustodyRefusalIdentityChirho::CustodyFrameInvalidChirho,
            "the wrapped key is not in form",
        ));
    }
    if !frame_chirho.frame_digest_chirho.is_empty()
        && !valid_lower_hex_chirho(&frame_chirho.frame_digest_chirho, DIGEST_HEX_BYTES_CHIRHO)
    {
        return Err(refuse_chirho(
            KeyCustodyRefusalIdentityChirho::CustodyFrameInvalidChirho,
            "the frame digest is not canonical hex",
        ));
    }
    Ok(())
}

fn frame_digest_hex_chirho(frame_chirho: &CustodyFrameV1Chirho) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(CUSTODY_FRAME_DIGEST_DOMAIN_V1_CHIRHO);
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"schema-chirho",
        frame_chirho.schema_chirho.as_bytes(),
    );
    frame_chirho
        .binding_chirho
        .update_digest_chirho(&mut hasher_chirho);
    update_lease_field_chirho(
        &mut hasher_chirho,
        frame_chirho.leader_lease_remaining_millis_chirho,
    );
    let wrapped_chirho = &frame_chirho.wrapped_key_chirho;
    for (label_chirho, value_chirho) in [
        (
            &b"ephemeral-public-chirho"[..],
            &wrapped_chirho.ephemeral_public_hex_chirho,
        ),
        (&b"nonce-chirho"[..], &wrapped_chirho.nonce_hex_chirho),
        (
            &b"ciphertext-chirho"[..],
            &wrapped_chirho.ciphertext_hex_chirho,
        ),
    ] {
        update_digest_field_chirho(&mut hasher_chirho, label_chirho, value_chirho.as_bytes());
    }
    hasher_chirho.finalize().to_hex().to_string()
}

fn wire_invalid_chirho() -> KeyCustodyErrorChirho {
    refuse_chirho(
        KeyCustodyRefusalIdentityChirho::CustodyWireInvalidChirho,
        "the custody frame wire bytes are too large or do not parse",
    )
}
