// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use crate::{RelayContractErrorChirho, RelayRefusalIdentityChirho};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

mod headers_chirho;
mod ingress_chirho;
pub use headers_chirho::{
    relay_request_header_name_is_allowed_chirho, relay_response_header_name_is_allowed_chirho,
    RelayEndToEndHeadersChirho,
};
use headers_chirho::{update_headers_digest_chirho, RelayHeaderKindChirho};
pub use ingress_chirho::{RelayIngressAdmissionChirho, RelayIngressScopeChirho};

pub const SERVED_WRITE_RELAY_REQUEST_SCHEMA_V1_CHIRHO: &str =
    "served-write-relay-request-v1-chirho";
pub const SERVED_WRITE_RELAY_RESPONSE_SCHEMA_V1_CHIRHO: &str =
    "served-write-relay-response-v1-chirho";
pub const CALLER_IDEMPOTENCY_KEY_HEADER_CHIRHO: &str = "cairn-idempotency-key-chirho";
pub const CALLER_IDEMPOTENCY_KEY_MAX_BYTES_CHIRHO: usize = 128;
pub const RELAY_BODY_MAX_BYTES_CHIRHO: usize = 2 * 1024 * 1024;
pub const RELAY_RESPONSE_BODY_MAX_BYTES_CHIRHO: usize = 2 * 1024 * 1024;

const RELAY_REQUEST_DIGEST_DOMAIN_V1_CHIRHO: &[u8] = b"cairn-served-write-relay-request-v1-chirho";
const RELAY_RESPONSE_DIGEST_DOMAIN_V1_CHIRHO: &[u8] =
    b"cairn-served-write-relay-response-v1-chirho";
const RELAY_TENANT_GROUP_DIGEST_DOMAIN_V1_CHIRHO: &[u8] =
    b"cairn-served-write-relay-tenant-group-v1-chirho";
const CALLER_IDEMPOTENCY_KEY_DIGEST_DOMAIN_V1_CHIRHO: &[u8] =
    b"cairn-caller-idempotency-key-v1-chirho";
const CALLER_OPERATION_BINDING_DIGEST_DOMAIN_V1_CHIRHO: &[u8] =
    b"cairn-caller-operation-binding-v1-chirho";
const RELAY_NODE_ID_HEX_BYTES_CHIRHO: usize = 64;
const RELAY_DIGEST_HEX_BYTES_CHIRHO: usize = 64;
const RELAY_SIGNATURE_HEX_BYTES_CHIRHO: usize = 128;
const RELAY_METHOD_MAX_BYTES_CHIRHO: usize = 16;
const RELAY_URI_MAX_BYTES_CHIRHO: usize = 8 * 1024;
const RELAY_ROSTER_MAX_MEMBERS_CHIRHO: usize = 64;
const RELAY_BUDGET_MAX_MILLIS_CHIRHO: u64 = 120_000;
const RELAY_OUTCOME_IDENTITY_MAX_BYTES_CHIRHO: usize = 128;
pub const RELAY_REQUEST_WIRE_MAX_BYTES_CHIRHO: usize = 3 * 1024 * 1024;
pub const RELAY_RESPONSE_WIRE_MAX_BYTES_CHIRHO: usize = 3 * 1024 * 1024;

/// Derive the one cross-host-stable relay identity for a tenant-root consistency group.
///
/// Host composition must first establish that its selected writer group is the tenant variant.
/// Canonical root paths are intentionally rejected here because two hosts need not mount the same
/// logical tenant at the same pathname.
pub fn relay_tenant_consistency_group_digest_chirho(
    tenant_id_chirho: &str,
) -> Result<String, RelayContractErrorChirho> {
    if tenant_id_chirho.is_empty()
        || tenant_id_chirho.len() > 64
        || tenant_id_chirho.starts_with('-')
        || tenant_id_chirho.ends_with('-')
        || !tenant_id_chirho.bytes().all(|byte_chirho| {
            byte_chirho.is_ascii_lowercase() || byte_chirho.is_ascii_digit() || byte_chirho == b'-'
        })
    {
        return Err(RelayContractErrorChirho::new_chirho(
            RelayRefusalIdentityChirho::RelayConsistencyGroupMismatchChirho,
            "relay tenant consistency group is not a canonical tenant id",
        ));
    }

    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(RELAY_TENANT_GROUP_DIGEST_DOMAIN_V1_CHIRHO);
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"tenant-id-chirho",
        tenant_id_chirho.as_bytes(),
    );
    Ok(hasher_chirho.finalize().to_hex().to_string())
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct CallerIdempotencyKeyChirho(String);

impl CallerIdempotencyKeyChirho {
    pub fn new_chirho(key_chirho: impl Into<String>) -> Result<Self, RelayContractErrorChirho> {
        let key_chirho = key_chirho.into();
        validate_caller_key_chirho(&key_chirho)?;
        Ok(Self(key_chirho))
    }

    pub fn as_str_chirho(&self) -> &str {
        &self.0
    }

    pub fn digest_hex_chirho(&self) -> String {
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(CALLER_IDEMPOTENCY_KEY_DIGEST_DOMAIN_V1_CHIRHO);
        update_digest_field_chirho(&mut hasher_chirho, b"key-chirho", self.0.as_bytes());
        hasher_chirho.finalize().to_hex().to_string()
    }
}

impl fmt::Debug for CallerIdempotencyKeyChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str("CallerIdempotencyKeyChirho(<redacted>)")
    }
}

/// Canonical HTTP operation coordinates bound beside a caller idempotency key.
///
/// The raw method and URI cross the signed relay envelope, but only this value's domain-separated
/// digest enters the durable run-intent log. Keeping the key and operation as distinct values lets a
/// retry reuse one key while making a changed method or URI a durable collision.
#[derive(Clone, PartialEq, Eq)]
pub struct CallerOperationBindingChirho {
    method_chirho: String,
    normalized_uri_chirho: String,
}

impl CallerOperationBindingChirho {
    pub fn new_chirho(
        method_chirho: impl Into<String>,
        normalized_uri_chirho: impl Into<String>,
    ) -> Result<Self, RelayContractErrorChirho> {
        let method_chirho = method_chirho.into();
        let normalized_uri_chirho = normalized_uri_chirho.into();
        if !valid_method_chirho(&method_chirho) {
            return Err(RelayContractErrorChirho::new_chirho(
                RelayRefusalIdentityChirho::RelayMethodInvalidChirho,
                "caller operation method is not canonical and bounded",
            ));
        }
        if !valid_normalized_uri_chirho(&normalized_uri_chirho) {
            return Err(RelayContractErrorChirho::new_chirho(
                RelayRefusalIdentityChirho::RelayUriInvalidChirho,
                "caller operation URI is not normalized and bounded",
            ));
        }
        Ok(Self {
            method_chirho,
            normalized_uri_chirho,
        })
    }

    pub fn method_chirho(&self) -> &str {
        &self.method_chirho
    }

    pub fn normalized_uri_chirho(&self) -> &str {
        &self.normalized_uri_chirho
    }

    pub fn digest_hex_chirho(&self) -> String {
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(CALLER_OPERATION_BINDING_DIGEST_DOMAIN_V1_CHIRHO);
        update_digest_field_chirho(
            &mut hasher_chirho,
            b"method-chirho",
            self.method_chirho.as_bytes(),
        );
        update_digest_field_chirho(
            &mut hasher_chirho,
            b"normalized-uri-chirho",
            self.normalized_uri_chirho.as_bytes(),
        );
        hasher_chirho.finalize().to_hex().to_string()
    }
}

impl fmt::Debug for CallerOperationBindingChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str("CallerOperationBindingChirho(<redacted>)")
    }
}

impl<'de> Deserialize<'de> for CallerIdempotencyKeyChirho {
    fn deserialize<DeserializerChirho>(
        deserializer_chirho: DeserializerChirho,
    ) -> Result<Self, DeserializerChirho::Error>
    where
        DeserializerChirho: serde::Deserializer<'de>,
    {
        let key_chirho = String::deserialize(deserializer_chirho)?;
        Self::new_chirho(key_chirho).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayRosterChirho {
    members_chirho: BTreeSet<String>,
    digest_chirho: [u8; 32],
}

impl RelayRosterChirho {
    pub fn new_chirho(
        members_chirho: impl IntoIterator<Item = String>,
    ) -> Result<Self, RelayContractErrorChirho> {
        let mut exact_members_chirho = BTreeSet::new();
        for member_chirho in members_chirho {
            if !valid_lower_hex_chirho(&member_chirho, RELAY_NODE_ID_HEX_BYTES_CHIRHO)
                || !exact_members_chirho.insert(member_chirho)
            {
                return Err(RelayContractErrorChirho::new_chirho(
                    RelayRefusalIdentityChirho::RelayOriginNodeInvalidChirho,
                    "relay roster contains an invalid or duplicate node id",
                ));
            }
        }
        if exact_members_chirho.is_empty()
            || exact_members_chirho.len() > RELAY_ROSTER_MAX_MEMBERS_CHIRHO
        {
            return Err(RelayContractErrorChirho::new_chirho(
                RelayRefusalIdentityChirho::RelayOriginNodeInvalidChirho,
                "relay roster is empty or exceeds its fixed bound",
            ));
        }
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(b"cairn-relay-origin-population-v1-chirho");
        for member_chirho in &exact_members_chirho {
            update_digest_field_chirho(
                &mut hasher_chirho,
                b"origin-chirho",
                member_chirho.as_bytes(),
            );
        }
        Ok(Self {
            members_chirho: exact_members_chirho,
            digest_chirho: *hasher_chirho.finalize().as_bytes(),
        })
    }

    pub fn contains_chirho(&self, node_id_chirho: &str) -> bool {
        self.members_chirho.contains(node_id_chirho)
    }
}

pub struct ServedWriteRelayRequestInputChirho {
    pub origin_node_id_chirho: String,
    pub target_node_id_chirho: String,
    pub consistency_group_digest_chirho: String,
    pub expected_term_chirho: u64,
    pub caller_idempotency_key_chirho: CallerIdempotencyKeyChirho,
    pub method_chirho: String,
    pub uri_chirho: String,
    pub end_to_end_headers_chirho: RelayEndToEndHeadersChirho,
    pub body_chirho: Vec<u8>,
    pub relay_budget_remaining_millis_chirho: u64,
    pub ingress_admission_chirho: Option<RelayIngressAdmissionChirho>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServedWriteRelayRequestV1Chirho {
    schema_chirho: String,
    origin_node_id_chirho: String,
    target_node_id_chirho: String,
    consistency_group_digest_chirho: String,
    expected_term_chirho: u64,
    hop_count_chirho: u8,
    caller_idempotency_key_chirho: CallerIdempotencyKeyChirho,
    method_chirho: String,
    uri_chirho: String,
    end_to_end_headers_chirho: RelayEndToEndHeadersChirho,
    #[serde(with = "base64_bytes_chirho")]
    body_chirho: Vec<u8>,
    body_digest_chirho: String,
    relay_budget_remaining_millis_chirho: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ingress_admission_chirho: Option<RelayIngressAdmissionChirho>,
    request_digest_chirho: String,
    sig_hex_chirho: String,
}

pub struct PreparedServedWriteRelayRequestV1Chirho {
    request_chirho: ServedWriteRelayRequestV1Chirho,
}

impl PreparedServedWriteRelayRequestV1Chirho {
    pub fn new_chirho(
        input_chirho: ServedWriteRelayRequestInputChirho,
    ) -> Result<Self, RelayContractErrorChirho> {
        let body_digest_chirho = blake3::hash(&input_chirho.body_chirho).to_hex().to_string();
        let mut request_chirho = ServedWriteRelayRequestV1Chirho {
            schema_chirho: SERVED_WRITE_RELAY_REQUEST_SCHEMA_V1_CHIRHO.to_string(),
            origin_node_id_chirho: input_chirho.origin_node_id_chirho,
            target_node_id_chirho: input_chirho.target_node_id_chirho,
            consistency_group_digest_chirho: input_chirho.consistency_group_digest_chirho,
            expected_term_chirho: input_chirho.expected_term_chirho,
            hop_count_chirho: 1,
            caller_idempotency_key_chirho: input_chirho.caller_idempotency_key_chirho,
            method_chirho: input_chirho.method_chirho,
            uri_chirho: input_chirho.uri_chirho,
            end_to_end_headers_chirho: input_chirho.end_to_end_headers_chirho,
            body_chirho: input_chirho.body_chirho,
            body_digest_chirho,
            relay_budget_remaining_millis_chirho: input_chirho.relay_budget_remaining_millis_chirho,
            ingress_admission_chirho: input_chirho.ingress_admission_chirho,
            request_digest_chirho: String::new(),
            sig_hex_chirho: String::new(),
        };
        validate_request_semantics_chirho(&request_chirho)?;
        request_chirho.request_digest_chirho = request_digest_hex_chirho(&request_chirho);
        Ok(Self { request_chirho })
    }

    pub fn signing_digest_chirho(&self) -> [u8; 32] {
        decode_hex_32_chirho(&self.request_chirho.request_digest_chirho)
            .expect("prepared request always carries a validated digest")
    }

    pub fn into_signed_chirho(
        mut self,
        sig_hex_chirho: String,
    ) -> Result<ServedWriteRelayRequestV1Chirho, RelayContractErrorChirho> {
        validate_signature_hex_chirho(
            &sig_hex_chirho,
            RelayRefusalIdentityChirho::RelayRequestSignatureInvalidChirho,
        )?;
        self.request_chirho.sig_hex_chirho = sig_hex_chirho;
        Ok(self.request_chirho)
    }
}

impl ServedWriteRelayRequestV1Chirho {
    pub fn to_wire_bytes_chirho(&self) -> Result<Vec<u8>, RelayContractErrorChirho> {
        let bytes_chirho =
            serde_json::to_vec(self).map_err(|_| relay_wire_decode_error_chirho())?;
        if bytes_chirho.len() > RELAY_REQUEST_WIRE_MAX_BYTES_CHIRHO {
            return Err(relay_wire_too_large_error_chirho());
        }
        Ok(bytes_chirho)
    }
}

pub struct AuthenticatedServedWriteRelayRequestChirho {
    request_chirho: ServedWriteRelayRequestV1Chirho,
}

impl AuthenticatedServedWriteRelayRequestChirho {
    pub fn target_node_id_chirho(&self) -> &str {
        &self.request_chirho.target_node_id_chirho
    }

    pub fn consistency_group_digest_chirho(&self) -> &str {
        &self.request_chirho.consistency_group_digest_chirho
    }

    pub fn expected_term_chirho(&self) -> u64 {
        self.request_chirho.expected_term_chirho
    }

    pub fn caller_idempotency_key_chirho(&self) -> &CallerIdempotencyKeyChirho {
        &self.request_chirho.caller_idempotency_key_chirho
    }

    pub fn request_digest_chirho(&self) -> &str {
        &self.request_chirho.request_digest_chirho
    }

    pub fn bind_destination_chirho(
        &self,
        expected_group_digest_chirho: &str,
        expected_recipient_node_id_chirho: &str,
        roster_chirho: &RelayRosterChirho,
    ) -> Result<VerifiedServedWriteRelayRequestChirho, RelayContractErrorChirho> {
        if self.request_chirho.consistency_group_digest_chirho != expected_group_digest_chirho {
            return Err(RelayContractErrorChirho::new_chirho(
                RelayRefusalIdentityChirho::RelayConsistencyGroupMismatchChirho,
                "relay request consistency group does not match the selected root",
            ));
        }
        if self.request_chirho.target_node_id_chirho != expected_recipient_node_id_chirho
            || !roster_chirho.contains_chirho(expected_recipient_node_id_chirho)
        {
            return Err(RelayContractErrorChirho::new_chirho(
                RelayRefusalIdentityChirho::RelayRecipientMismatchChirho,
                "relay request recipient does not match this rostered node",
            ));
        }
        Ok(VerifiedServedWriteRelayRequestChirho {
            request_chirho: self.request_chirho.clone(),
            roster_digest_chirho: roster_chirho.digest_chirho,
        })
    }
}

pub struct VerifiedServedWriteRelayRequestChirho {
    request_chirho: ServedWriteRelayRequestV1Chirho,
    roster_digest_chirho: [u8; 32],
}

impl VerifiedServedWriteRelayRequestChirho {
    pub fn ingress_admission_chirho(&self) -> Option<&RelayIngressAdmissionChirho> {
        self.request_chirho.ingress_admission_chirho.as_ref()
    }

    pub fn origin_node_id_chirho(&self) -> &str {
        &self.request_chirho.origin_node_id_chirho
    }

    pub fn target_node_id_chirho(&self) -> &str {
        &self.request_chirho.target_node_id_chirho
    }

    pub fn consistency_group_digest_chirho(&self) -> &str {
        &self.request_chirho.consistency_group_digest_chirho
    }

    pub fn expected_term_chirho(&self) -> u64 {
        self.request_chirho.expected_term_chirho
    }

    pub fn caller_idempotency_key_chirho(&self) -> &CallerIdempotencyKeyChirho {
        &self.request_chirho.caller_idempotency_key_chirho
    }

    pub fn method_chirho(&self) -> &str {
        &self.request_chirho.method_chirho
    }

    pub fn uri_chirho(&self) -> &str {
        &self.request_chirho.uri_chirho
    }

    pub fn end_to_end_headers_chirho(&self) -> &RelayEndToEndHeadersChirho {
        &self.request_chirho.end_to_end_headers_chirho
    }

    pub fn body_chirho(&self) -> &[u8] {
        &self.request_chirho.body_chirho
    }

    pub fn relay_budget_remaining_millis_chirho(&self) -> u64 {
        self.request_chirho.relay_budget_remaining_millis_chirho
    }

    pub fn request_digest_chirho(&self) -> &str {
        &self.request_chirho.request_digest_chirho
    }
}

#[derive(Clone)]
pub struct PreparedServedWriteRelayAttemptChirho {
    signed_request_wire_chirho: Vec<u8>,
    request_digest_chirho: String,
    caller_key_digest_chirho: String,
    consistency_group_digest_chirho: String,
    target_node_id_chirho: String,
    expected_term_chirho: u64,
}

impl PreparedServedWriteRelayAttemptChirho {
    pub fn new_chirho(
        signed_request_chirho: ServedWriteRelayRequestV1Chirho,
        expected_group_digest_chirho: &str,
        expected_target_node_id_chirho: &str,
        roster_chirho: &RelayRosterChirho,
    ) -> Result<Self, RelayContractErrorChirho> {
        let signed_request_wire_chirho = signed_request_chirho.to_wire_bytes_chirho()?;
        let verified_chirho = decode_and_verify_served_write_relay_request_chirho(
            &signed_request_wire_chirho,
            expected_group_digest_chirho,
            expected_target_node_id_chirho,
            roster_chirho,
        )?;
        Ok(Self {
            request_digest_chirho: verified_chirho.request_digest_chirho().to_string(),
            caller_key_digest_chirho: verified_chirho
                .caller_idempotency_key_chirho()
                .digest_hex_chirho(),
            consistency_group_digest_chirho: verified_chirho
                .consistency_group_digest_chirho()
                .to_string(),
            target_node_id_chirho: verified_chirho.target_node_id_chirho().to_string(),
            expected_term_chirho: verified_chirho.expected_term_chirho(),
            signed_request_wire_chirho,
        })
    }

    pub fn signed_request_wire_chirho(&self) -> &[u8] {
        &self.signed_request_wire_chirho
    }

    pub fn request_digest_chirho(&self) -> &str {
        &self.request_digest_chirho
    }

    pub fn caller_key_digest_chirho(&self) -> &str {
        &self.caller_key_digest_chirho
    }

    pub fn consistency_group_digest_chirho(&self) -> &str {
        &self.consistency_group_digest_chirho
    }

    pub fn target_node_id_chirho(&self) -> &str {
        &self.target_node_id_chirho
    }

    pub fn expected_term_chirho(&self) -> u64 {
        self.expected_term_chirho
    }

    pub fn require_resolution_chirho(
        &self,
        group_digest_chirho: &str,
        target_node_id_chirho: &str,
        term_chirho: u64,
    ) -> Result<(), RelayContractErrorChirho> {
        if self.consistency_group_digest_chirho != group_digest_chirho {
            return Err(RelayContractErrorChirho::new_chirho(
                RelayRefusalIdentityChirho::RelayConsistencyGroupMismatchChirho,
                "prepared relay attempt does not match the resolved consistency group",
            ));
        }
        if self.target_node_id_chirho != target_node_id_chirho {
            return Err(RelayContractErrorChirho::new_chirho(
                RelayRefusalIdentityChirho::RelayRecipientMismatchChirho,
                "prepared relay attempt does not match the resolved owner",
            ));
        }
        if self.expected_term_chirho != term_chirho {
            return Err(RelayContractErrorChirho::new_chirho(
                RelayRefusalIdentityChirho::RelayOwnerTermChangedChirho,
                "prepared relay attempt term differs from the resolved owner term",
            ));
        }
        Ok(())
    }

    pub fn verify_response_chirho(
        &self,
        wire_bytes_chirho: &[u8],
        roster_chirho: &RelayRosterChirho,
    ) -> Result<VerifiedServedWriteRelayResponseChirho, RelayContractErrorChirho> {
        let verified_chirho = decode_and_verify_served_write_relay_response_chirho(
            wire_bytes_chirho,
            &self.request_digest_chirho,
            &self.caller_key_digest_chirho,
            &self.consistency_group_digest_chirho,
            &self.target_node_id_chirho,
            roster_chirho,
        )?;
        if verified_chirho.actual_term_chirho() != self.expected_term_chirho
            && !(verified_chirho.outcome_class_chirho()
                == RelayOutcomeClassChirho::RelayRefusalChirho
                && matches!(
                    verified_chirho.outcome_identity_chirho(),
                    Some(identity_chirho)
                        if identity_chirho
                            == RelayRefusalIdentityChirho::RelayOwnerTermChangedChirho
                                .as_str_chirho()
                            || identity_chirho
                                == RelayRefusalIdentityChirho::RelayConsistencyGroupMismatchChirho
                                    .as_str_chirho()
                ))
        {
            return Err(RelayContractErrorChirho::new_chirho(
                RelayRefusalIdentityChirho::RelayResponseAuthenticationRefusedChirho,
                "relay response term differs without the exact signed term-change refusal",
            )
            .after_request_may_have_executed_chirho());
        }
        Ok(verified_chirho)
    }
}

pub fn decode_and_verify_served_write_relay_request_chirho(
    wire_bytes_chirho: &[u8],
    expected_group_digest_chirho: &str,
    expected_recipient_node_id_chirho: &str,
    roster_chirho: &RelayRosterChirho,
) -> Result<VerifiedServedWriteRelayRequestChirho, RelayContractErrorChirho> {
    decode_and_authenticate_served_write_relay_request_chirho(wire_bytes_chirho, roster_chirho)?
        .bind_destination_chirho(
            expected_group_digest_chirho,
            expected_recipient_node_id_chirho,
            roster_chirho,
        )
}

pub fn decode_and_authenticate_served_write_relay_request_chirho(
    wire_bytes_chirho: &[u8],
    roster_chirho: &RelayRosterChirho,
) -> Result<AuthenticatedServedWriteRelayRequestChirho, RelayContractErrorChirho> {
    if wire_bytes_chirho.len() > RELAY_REQUEST_WIRE_MAX_BYTES_CHIRHO {
        return Err(relay_wire_too_large_error_chirho());
    }
    let request_chirho: ServedWriteRelayRequestV1Chirho =
        serde_json::from_slice(wire_bytes_chirho).map_err(|_| relay_wire_decode_error_chirho())?;
    validate_request_semantics_chirho(&request_chirho)?;
    if !roster_chirho.contains_chirho(&request_chirho.origin_node_id_chirho) {
        return Err(RelayContractErrorChirho::new_chirho(
            RelayRefusalIdentityChirho::RelayOriginUnrosteredChirho,
            "relay request origin is not in the exact active roster",
        ));
    }
    let expected_request_digest_chirho = request_digest_hex_chirho(&request_chirho);
    if request_chirho.request_digest_chirho != expected_request_digest_chirho {
        return Err(RelayContractErrorChirho::new_chirho(
            RelayRefusalIdentityChirho::RelayRequestDigestMismatchChirho,
            "relay request digest does not bind its semantic fields",
        ));
    }
    verify_node_signature_chirho(
        &request_chirho.origin_node_id_chirho,
        &request_chirho.request_digest_chirho,
        &request_chirho.sig_hex_chirho,
        RelayRefusalIdentityChirho::RelayRequestSignatureInvalidChirho,
    )?;
    Ok(AuthenticatedServedWriteRelayRequestChirho { request_chirho })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayOutcomeClassChirho {
    #[serde(rename = "served-response-chirho")]
    ServedResponseChirho,
    #[serde(rename = "door-refusal-chirho")]
    DoorRefusalChirho,
    #[serde(rename = "relay-refusal-chirho")]
    RelayRefusalChirho,
}

pub struct ServedWriteRelayResponseInputChirho {
    pub request_digest_chirho: String,
    pub caller_idempotency_key_digest_chirho: String,
    pub responder_node_id_chirho: String,
    pub consistency_group_digest_chirho: String,
    pub actual_term_chirho: u64,
    pub outcome_class_chirho: RelayOutcomeClassChirho,
    pub outcome_identity_chirho: Option<String>,
    pub status_chirho: u16,
    pub end_to_end_headers_chirho: RelayEndToEndHeadersChirho,
    pub body_chirho: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServedWriteRelayResponseV1Chirho {
    schema_chirho: String,
    request_digest_chirho: String,
    caller_idempotency_key_digest_chirho: String,
    responder_node_id_chirho: String,
    consistency_group_digest_chirho: String,
    actual_term_chirho: u64,
    outcome_class_chirho: RelayOutcomeClassChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    outcome_identity_chirho: Option<String>,
    status_chirho: u16,
    end_to_end_headers_chirho: RelayEndToEndHeadersChirho,
    #[serde(with = "base64_bytes_chirho")]
    body_chirho: Vec<u8>,
    body_digest_chirho: String,
    response_digest_chirho: String,
    sig_hex_chirho: String,
}

pub struct PreparedServedWriteRelayResponseV1Chirho {
    response_chirho: ServedWriteRelayResponseV1Chirho,
}

impl PreparedServedWriteRelayResponseV1Chirho {
    pub fn new_chirho(
        input_chirho: ServedWriteRelayResponseInputChirho,
    ) -> Result<Self, RelayContractErrorChirho> {
        let body_digest_chirho = blake3::hash(&input_chirho.body_chirho).to_hex().to_string();
        let mut response_chirho = ServedWriteRelayResponseV1Chirho {
            schema_chirho: SERVED_WRITE_RELAY_RESPONSE_SCHEMA_V1_CHIRHO.to_string(),
            request_digest_chirho: input_chirho.request_digest_chirho,
            caller_idempotency_key_digest_chirho: input_chirho.caller_idempotency_key_digest_chirho,
            responder_node_id_chirho: input_chirho.responder_node_id_chirho,
            consistency_group_digest_chirho: input_chirho.consistency_group_digest_chirho,
            actual_term_chirho: input_chirho.actual_term_chirho,
            outcome_class_chirho: input_chirho.outcome_class_chirho,
            outcome_identity_chirho: input_chirho.outcome_identity_chirho,
            status_chirho: input_chirho.status_chirho,
            end_to_end_headers_chirho: input_chirho.end_to_end_headers_chirho,
            body_chirho: input_chirho.body_chirho,
            body_digest_chirho,
            response_digest_chirho: String::new(),
            sig_hex_chirho: String::new(),
        };
        validate_response_semantics_chirho(&response_chirho)?;
        response_chirho.response_digest_chirho = response_digest_hex_chirho(&response_chirho);
        Ok(Self { response_chirho })
    }

    pub fn signing_digest_chirho(&self) -> [u8; 32] {
        decode_hex_32_chirho(&self.response_chirho.response_digest_chirho)
            .expect("prepared response always carries a validated digest")
    }

    pub fn into_signed_chirho(
        mut self,
        sig_hex_chirho: String,
    ) -> Result<ServedWriteRelayResponseV1Chirho, RelayContractErrorChirho> {
        validate_signature_hex_chirho(
            &sig_hex_chirho,
            RelayRefusalIdentityChirho::RelayResponseAuthenticationRefusedChirho,
        )?;
        self.response_chirho.sig_hex_chirho = sig_hex_chirho;
        Ok(self.response_chirho)
    }
}

impl ServedWriteRelayResponseV1Chirho {
    pub fn to_wire_bytes_chirho(&self) -> Result<Vec<u8>, RelayContractErrorChirho> {
        let bytes_chirho =
            serde_json::to_vec(self).map_err(|_| relay_wire_decode_error_chirho())?;
        if bytes_chirho.len() > RELAY_RESPONSE_WIRE_MAX_BYTES_CHIRHO {
            return Err(relay_wire_too_large_error_chirho());
        }
        Ok(bytes_chirho)
    }
}

pub struct VerifiedServedWriteRelayResponseChirho {
    response_chirho: ServedWriteRelayResponseV1Chirho,
}

impl VerifiedServedWriteRelayResponseChirho {
    pub fn actual_term_chirho(&self) -> u64 {
        self.response_chirho.actual_term_chirho
    }

    pub fn consistency_group_digest_chirho(&self) -> &str {
        &self.response_chirho.consistency_group_digest_chirho
    }

    pub fn outcome_class_chirho(&self) -> RelayOutcomeClassChirho {
        self.response_chirho.outcome_class_chirho
    }

    pub fn outcome_identity_chirho(&self) -> Option<&str> {
        self.response_chirho.outcome_identity_chirho.as_deref()
    }

    pub fn status_chirho(&self) -> u16 {
        self.response_chirho.status_chirho
    }

    pub fn end_to_end_headers_chirho(&self) -> &RelayEndToEndHeadersChirho {
        &self.response_chirho.end_to_end_headers_chirho
    }

    pub fn body_chirho(&self) -> &[u8] {
        &self.response_chirho.body_chirho
    }
}

pub fn decode_and_verify_served_write_relay_response_chirho(
    wire_bytes_chirho: &[u8],
    expected_request_digest_chirho: &str,
    expected_caller_key_digest_chirho: &str,
    expected_group_digest_chirho: &str,
    expected_responder_node_id_chirho: &str,
    roster_chirho: &RelayRosterChirho,
) -> Result<VerifiedServedWriteRelayResponseChirho, RelayContractErrorChirho> {
    decode_and_verify_served_write_relay_response_inner_chirho(
        wire_bytes_chirho,
        expected_request_digest_chirho,
        expected_caller_key_digest_chirho,
        expected_group_digest_chirho,
        expected_responder_node_id_chirho,
        roster_chirho,
    )
    .map_err(RelayContractErrorChirho::after_request_may_have_executed_chirho)
}

fn decode_and_verify_served_write_relay_response_inner_chirho(
    wire_bytes_chirho: &[u8],
    expected_request_digest_chirho: &str,
    expected_caller_key_digest_chirho: &str,
    expected_group_digest_chirho: &str,
    expected_responder_node_id_chirho: &str,
    roster_chirho: &RelayRosterChirho,
) -> Result<VerifiedServedWriteRelayResponseChirho, RelayContractErrorChirho> {
    if wire_bytes_chirho.len() > RELAY_RESPONSE_WIRE_MAX_BYTES_CHIRHO {
        return Err(relay_wire_too_large_error_chirho());
    }
    let response_chirho: ServedWriteRelayResponseV1Chirho =
        serde_json::from_slice(wire_bytes_chirho).map_err(|_| relay_wire_decode_error_chirho())?;
    validate_response_semantics_chirho(&response_chirho)?;
    if response_chirho.request_digest_chirho != expected_request_digest_chirho
        || response_chirho.caller_idempotency_key_digest_chirho != expected_caller_key_digest_chirho
        || response_chirho.responder_node_id_chirho != expected_responder_node_id_chirho
        || !roster_chirho.contains_chirho(expected_responder_node_id_chirho)
    {
        return Err(RelayContractErrorChirho::new_chirho(
            RelayRefusalIdentityChirho::RelayResponseAuthenticationRefusedChirho,
            "relay response does not bind the expected request, caller key, group, and responder",
        ));
    }
    let expected_response_digest_chirho = response_digest_hex_chirho(&response_chirho);
    if response_chirho.response_digest_chirho != expected_response_digest_chirho {
        return Err(RelayContractErrorChirho::new_chirho(
            RelayRefusalIdentityChirho::RelayResponseDigestMismatchChirho,
            "relay response digest does not bind its semantic fields",
        ));
    }
    verify_node_signature_chirho(
        &response_chirho.responder_node_id_chirho,
        &response_chirho.response_digest_chirho,
        &response_chirho.sig_hex_chirho,
        RelayRefusalIdentityChirho::RelayResponseAuthenticationRefusedChirho,
    )?;
    let exact_group_mismatch_chirho = response_chirho.outcome_class_chirho
        == RelayOutcomeClassChirho::RelayRefusalChirho
        && response_chirho.outcome_identity_chirho.as_deref()
            == Some(
                RelayRefusalIdentityChirho::RelayConsistencyGroupMismatchChirho.as_str_chirho(),
            );
    if (response_chirho.consistency_group_digest_chirho == expected_group_digest_chirho)
        == exact_group_mismatch_chirho
    {
        return Err(RelayContractErrorChirho::new_chirho(
            RelayRefusalIdentityChirho::RelayResponseAuthenticationRefusedChirho,
            "relay response group binding disagrees with its signed outcome",
        ));
    }
    Ok(VerifiedServedWriteRelayResponseChirho { response_chirho })
}

fn validate_request_semantics_chirho(
    request_chirho: &ServedWriteRelayRequestV1Chirho,
) -> Result<(), RelayContractErrorChirho> {
    if let Some(admission_chirho) = &request_chirho.ingress_admission_chirho {
        admission_chirho.validate_chirho()?;
    }
    if request_chirho.schema_chirho != SERVED_WRITE_RELAY_REQUEST_SCHEMA_V1_CHIRHO {
        return Err(RelayContractErrorChirho::new_chirho(
            RelayRefusalIdentityChirho::RelaySchemaUnsupportedChirho,
            "relay request schema is unsupported",
        ));
    }
    if !valid_lower_hex_chirho(
        &request_chirho.origin_node_id_chirho,
        RELAY_NODE_ID_HEX_BYTES_CHIRHO,
    ) || !valid_lower_hex_chirho(
        &request_chirho.target_node_id_chirho,
        RELAY_NODE_ID_HEX_BYTES_CHIRHO,
    ) {
        return Err(RelayContractErrorChirho::new_chirho(
            RelayRefusalIdentityChirho::RelayOriginNodeInvalidChirho,
            "relay request node ids must be canonical public-key hex",
        ));
    }
    if !valid_lower_hex_chirho(
        &request_chirho.consistency_group_digest_chirho,
        RELAY_DIGEST_HEX_BYTES_CHIRHO,
    ) {
        return Err(RelayContractErrorChirho::new_chirho(
            RelayRefusalIdentityChirho::RelayConsistencyGroupMismatchChirho,
            "relay request group digest is not canonical hex",
        ));
    }
    if request_chirho.expected_term_chirho == 0 {
        return Err(RelayContractErrorChirho::new_chirho(
            RelayRefusalIdentityChirho::RelayTermInvalidChirho,
            "relay request term must be nonzero",
        ));
    }
    if request_chirho.hop_count_chirho != 1 {
        return Err(RelayContractErrorChirho::new_chirho(
            RelayRefusalIdentityChirho::RelayHopInvalidChirho,
            "relay request hop count must be exactly one",
        ));
    }
    validate_caller_key_chirho(request_chirho.caller_idempotency_key_chirho.as_str_chirho())?;
    if !valid_method_chirho(&request_chirho.method_chirho) {
        return Err(RelayContractErrorChirho::new_chirho(
            RelayRefusalIdentityChirho::RelayMethodInvalidChirho,
            "relay request method is not canonical",
        ));
    }
    if !valid_normalized_uri_chirho(&request_chirho.uri_chirho) {
        return Err(RelayContractErrorChirho::new_chirho(
            RelayRefusalIdentityChirho::RelayUriInvalidChirho,
            "relay request URI is not normalized and bounded",
        ));
    }
    request_chirho
        .end_to_end_headers_chirho
        .validate_chirho(RelayHeaderKindChirho::RequestChirho)?;
    if request_chirho.body_chirho.len() > RELAY_BODY_MAX_BYTES_CHIRHO {
        return Err(RelayContractErrorChirho::new_chirho(
            RelayRefusalIdentityChirho::RelayBodyTooLargeChirho,
            "relay request body exceeds its fixed bound",
        ));
    }
    if request_chirho.body_digest_chirho
        != blake3::hash(&request_chirho.body_chirho)
            .to_hex()
            .to_string()
    {
        return Err(RelayContractErrorChirho::new_chirho(
            RelayRefusalIdentityChirho::RelayBodyDigestMismatchChirho,
            "relay request body digest does not verify",
        ));
    }
    if request_chirho.relay_budget_remaining_millis_chirho == 0
        || request_chirho.relay_budget_remaining_millis_chirho > RELAY_BUDGET_MAX_MILLIS_CHIRHO
    {
        return Err(RelayContractErrorChirho::new_chirho(
            RelayRefusalIdentityChirho::RelayBudgetInvalidChirho,
            "relay request remaining duration is absent or out of bounds",
        ));
    }
    if !request_chirho.request_digest_chirho.is_empty()
        && !valid_lower_hex_chirho(
            &request_chirho.request_digest_chirho,
            RELAY_DIGEST_HEX_BYTES_CHIRHO,
        )
    {
        return Err(RelayContractErrorChirho::new_chirho(
            RelayRefusalIdentityChirho::RelayRequestDigestMismatchChirho,
            "relay request digest is not canonical hex",
        ));
    }
    if !request_chirho.sig_hex_chirho.is_empty() {
        validate_signature_hex_chirho(
            &request_chirho.sig_hex_chirho,
            RelayRefusalIdentityChirho::RelayRequestSignatureInvalidChirho,
        )?;
    }
    Ok(())
}

fn validate_response_semantics_chirho(
    response_chirho: &ServedWriteRelayResponseV1Chirho,
) -> Result<(), RelayContractErrorChirho> {
    if response_chirho.schema_chirho != SERVED_WRITE_RELAY_RESPONSE_SCHEMA_V1_CHIRHO {
        return Err(RelayContractErrorChirho::new_chirho(
            RelayRefusalIdentityChirho::RelaySchemaUnsupportedChirho,
            "relay response schema is unsupported",
        ));
    }
    if !valid_lower_hex_chirho(
        &response_chirho.request_digest_chirho,
        RELAY_DIGEST_HEX_BYTES_CHIRHO,
    ) || !valid_lower_hex_chirho(
        &response_chirho.caller_idempotency_key_digest_chirho,
        RELAY_DIGEST_HEX_BYTES_CHIRHO,
    ) || !valid_lower_hex_chirho(
        &response_chirho.responder_node_id_chirho,
        RELAY_NODE_ID_HEX_BYTES_CHIRHO,
    ) || !valid_lower_hex_chirho(
        &response_chirho.consistency_group_digest_chirho,
        RELAY_DIGEST_HEX_BYTES_CHIRHO,
    ) {
        return Err(RelayContractErrorChirho::new_chirho(
            RelayRefusalIdentityChirho::RelayResponseAuthenticationRefusedChirho,
            "relay response identity bindings are not canonical hex",
        ));
    }
    if response_chirho.actual_term_chirho == 0 {
        return Err(RelayContractErrorChirho::new_chirho(
            RelayRefusalIdentityChirho::RelayTermInvalidChirho,
            "relay response term must be nonzero",
        ));
    }
    match (
        response_chirho.outcome_class_chirho,
        response_chirho.outcome_identity_chirho.as_deref(),
    ) {
        (RelayOutcomeClassChirho::ServedResponseChirho, None) => {}
        (RelayOutcomeClassChirho::DoorRefusalChirho, Some(identity_chirho))
            if valid_outcome_identity_chirho(identity_chirho)
                && body_names_outcome_identity_chirho(
                    &response_chirho.body_chirho,
                    identity_chirho,
                ) => {}
        (RelayOutcomeClassChirho::RelayRefusalChirho, Some(identity_chirho))
            if RelayRefusalIdentityChirho::from_str_chirho(identity_chirho).is_some() => {}
        _ => {
            return Err(RelayContractErrorChirho::new_chirho(
                RelayRefusalIdentityChirho::RelayResponseOutcomeInvalidChirho,
                "relay response outcome class and identity disagree",
            ))
        }
    }
    if !(200..=599).contains(&response_chirho.status_chirho) {
        return Err(RelayContractErrorChirho::new_chirho(
            RelayRefusalIdentityChirho::RelayResponseStatusInvalidChirho,
            "relay response HTTP status is outside the protocol range",
        ));
    }
    response_chirho
        .end_to_end_headers_chirho
        .validate_chirho(RelayHeaderKindChirho::ResponseChirho)?;
    if response_chirho.body_chirho.len() > RELAY_RESPONSE_BODY_MAX_BYTES_CHIRHO {
        return Err(RelayContractErrorChirho::new_chirho(
            RelayRefusalIdentityChirho::RelayBodyTooLargeChirho,
            "relay response body exceeds its fixed bound",
        ));
    }
    if response_chirho.body_digest_chirho
        != blake3::hash(&response_chirho.body_chirho)
            .to_hex()
            .to_string()
    {
        return Err(RelayContractErrorChirho::new_chirho(
            RelayRefusalIdentityChirho::RelayBodyDigestMismatchChirho,
            "relay response body digest does not verify",
        ));
    }
    if !response_chirho.response_digest_chirho.is_empty()
        && !valid_lower_hex_chirho(
            &response_chirho.response_digest_chirho,
            RELAY_DIGEST_HEX_BYTES_CHIRHO,
        )
    {
        return Err(RelayContractErrorChirho::new_chirho(
            RelayRefusalIdentityChirho::RelayResponseDigestMismatchChirho,
            "relay response digest is not canonical hex",
        ));
    }
    if !response_chirho.sig_hex_chirho.is_empty() {
        validate_signature_hex_chirho(
            &response_chirho.sig_hex_chirho,
            RelayRefusalIdentityChirho::RelayResponseAuthenticationRefusedChirho,
        )?;
    }
    Ok(())
}

fn request_digest_hex_chirho(request_chirho: &ServedWriteRelayRequestV1Chirho) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(RELAY_REQUEST_DIGEST_DOMAIN_V1_CHIRHO);
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"schema-chirho",
        request_chirho.schema_chirho.as_bytes(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"origin-node-id-chirho",
        request_chirho.origin_node_id_chirho.as_bytes(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"target-node-id-chirho",
        request_chirho.target_node_id_chirho.as_bytes(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"group-digest-chirho",
        request_chirho.consistency_group_digest_chirho.as_bytes(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"expected-term-chirho",
        &request_chirho.expected_term_chirho.to_le_bytes(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"hop-count-chirho",
        &[request_chirho.hop_count_chirho],
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"caller-idempotency-key-chirho",
        request_chirho
            .caller_idempotency_key_chirho
            .as_str_chirho()
            .as_bytes(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"method-chirho",
        request_chirho.method_chirho.as_bytes(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"uri-chirho",
        request_chirho.uri_chirho.as_bytes(),
    );
    update_headers_digest_chirho(
        &mut hasher_chirho,
        &request_chirho.end_to_end_headers_chirho,
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"body-chirho",
        &request_chirho.body_chirho,
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"body-digest-chirho",
        request_chirho.body_digest_chirho.as_bytes(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"relay-budget-remaining-millis-chirho",
        &request_chirho
            .relay_budget_remaining_millis_chirho
            .to_le_bytes(),
    );
    if let Some(admission_chirho) = &request_chirho.ingress_admission_chirho {
        admission_chirho.update_digest_chirho(&mut hasher_chirho);
    }
    hasher_chirho.finalize().to_hex().to_string()
}

fn response_digest_hex_chirho(response_chirho: &ServedWriteRelayResponseV1Chirho) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(RELAY_RESPONSE_DIGEST_DOMAIN_V1_CHIRHO);
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"schema-chirho",
        response_chirho.schema_chirho.as_bytes(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"request-digest-chirho",
        response_chirho.request_digest_chirho.as_bytes(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"caller-idempotency-key-digest-chirho",
        response_chirho
            .caller_idempotency_key_digest_chirho
            .as_bytes(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"responder-node-id-chirho",
        response_chirho.responder_node_id_chirho.as_bytes(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"group-digest-chirho",
        response_chirho.consistency_group_digest_chirho.as_bytes(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"actual-term-chirho",
        &response_chirho.actual_term_chirho.to_le_bytes(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"outcome-class-chirho",
        outcome_class_bytes_chirho(response_chirho.outcome_class_chirho),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"outcome-identity-chirho",
        response_chirho
            .outcome_identity_chirho
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"status-chirho",
        &response_chirho.status_chirho.to_le_bytes(),
    );
    update_headers_digest_chirho(
        &mut hasher_chirho,
        &response_chirho.end_to_end_headers_chirho,
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"body-chirho",
        &response_chirho.body_chirho,
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"body-digest-chirho",
        response_chirho.body_digest_chirho.as_bytes(),
    );
    hasher_chirho.finalize().to_hex().to_string()
}

fn update_digest_field_chirho(
    hasher_chirho: &mut blake3::Hasher,
    label_chirho: &[u8],
    bytes_chirho: &[u8],
) {
    hasher_chirho.update(&(label_chirho.len() as u64).to_le_bytes());
    hasher_chirho.update(label_chirho);
    hasher_chirho.update(&(bytes_chirho.len() as u64).to_le_bytes());
    hasher_chirho.update(bytes_chirho);
}

fn verify_node_signature_chirho(
    node_id_chirho: &str,
    digest_hex_chirho: &str,
    sig_hex_chirho: &str,
    identity_chirho: RelayRefusalIdentityChirho,
) -> Result<(), RelayContractErrorChirho> {
    let public_key_chirho = decode_hex_32_chirho(node_id_chirho).ok_or_else(|| {
        RelayContractErrorChirho::new_chirho(
            RelayRefusalIdentityChirho::RelayOriginNodeInvalidChirho,
            "relay signer node id is not a canonical public key",
        )
    })?;
    let digest_chirho = decode_hex_32_chirho(digest_hex_chirho).ok_or_else(|| {
        RelayContractErrorChirho::new_chirho(identity_chirho, "relay signed digest is invalid")
    })?;
    let signature_bytes_chirho = decode_hex_chirho(sig_hex_chirho).ok_or_else(|| {
        RelayContractErrorChirho::new_chirho(identity_chirho, "relay signature is invalid")
    })?;
    let signature_chirho = Signature::from_slice(&signature_bytes_chirho).map_err(|_| {
        RelayContractErrorChirho::new_chirho(identity_chirho, "relay signature is invalid")
    })?;
    let verifying_key_chirho = VerifyingKey::from_bytes(&public_key_chirho).map_err(|_| {
        RelayContractErrorChirho::new_chirho(identity_chirho, "relay signer key is invalid")
    })?;
    verifying_key_chirho
        .verify_strict(&digest_chirho, &signature_chirho)
        .map_err(|_| {
            RelayContractErrorChirho::new_chirho(identity_chirho, "relay signature does not verify")
        })
}

fn validate_caller_key_chirho(key_chirho: &str) -> Result<(), RelayContractErrorChirho> {
    if key_chirho.is_empty()
        || key_chirho.len() > CALLER_IDEMPOTENCY_KEY_MAX_BYTES_CHIRHO
        || !key_chirho
            .bytes()
            .all(|byte_chirho| (0x21..=0x7e).contains(&byte_chirho))
    {
        return Err(RelayContractErrorChirho::new_chirho(
            RelayRefusalIdentityChirho::RelayCallerKeyInvalidChirho,
            "caller idempotency key must be nonempty bounded visible ASCII",
        ));
    }
    Ok(())
}

fn validate_signature_hex_chirho(
    signature_chirho: &str,
    identity_chirho: RelayRefusalIdentityChirho,
) -> Result<(), RelayContractErrorChirho> {
    if !valid_lower_hex_chirho(signature_chirho, RELAY_SIGNATURE_HEX_BYTES_CHIRHO) {
        return Err(RelayContractErrorChirho::new_chirho(
            identity_chirho,
            "relay signature must be canonical lowercase hex",
        ));
    }
    Ok(())
}

fn valid_lower_hex_chirho(value_chirho: &str, exact_len_chirho: usize) -> bool {
    value_chirho.len() == exact_len_chirho
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}

fn valid_outcome_identity_chirho(identity_chirho: &str) -> bool {
    !identity_chirho.is_empty()
        && identity_chirho.len() <= RELAY_OUTCOME_IDENTITY_MAX_BYTES_CHIRHO
        && identity_chirho.ends_with("Chirho")
        && identity_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_alphanumeric())
}

fn body_names_outcome_identity_chirho(body_chirho: &[u8], identity_chirho: &str) -> bool {
    let Ok(body_chirho) = std::str::from_utf8(body_chirho) else {
        return false;
    };
    let Some(remainder_chirho) = body_chirho.strip_prefix("error: ") else {
        return false;
    };
    remainder_chirho
        .split(|character_chirho: char| {
            character_chirho == ':' || character_chirho.is_ascii_whitespace()
        })
        .next()
        == Some(identity_chirho)
}

fn valid_method_chirho(method_chirho: &str) -> bool {
    !method_chirho.is_empty()
        && method_chirho.len() <= RELAY_METHOD_MAX_BYTES_CHIRHO
        && method_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_uppercase() || byte_chirho == b'-')
}

fn valid_normalized_uri_chirho(uri_chirho: &str) -> bool {
    if uri_chirho.is_empty()
        || uri_chirho.len() > RELAY_URI_MAX_BYTES_CHIRHO
        || !uri_chirho.is_ascii()
        || !uri_chirho.starts_with('/')
        || uri_chirho.starts_with("//")
        || uri_chirho.ends_with('?')
        || uri_chirho.contains('#')
        || uri_chirho.contains('\\')
        || uri_chirho
            .bytes()
            .any(|byte_chirho| byte_chirho.is_ascii_control() || byte_chirho == b' ')
    {
        return false;
    }
    let path_chirho = uri_chirho
        .split_once('?')
        .map(|(path_chirho, _query_chirho)| path_chirho)
        .unwrap_or(uri_chirho);
    if path_chirho.contains("//")
        || path_chirho
            .split('/')
            .any(|segment_chirho| matches!(segment_chirho, "." | ".."))
    {
        return false;
    }
    let bytes_chirho = uri_chirho.as_bytes();
    let mut index_chirho = 0_usize;
    while index_chirho < bytes_chirho.len() {
        if bytes_chirho[index_chirho] != b'%' {
            index_chirho += 1;
            continue;
        }
        if index_chirho + 2 >= bytes_chirho.len()
            || !bytes_chirho[index_chirho + 1].is_ascii_hexdigit()
            || !bytes_chirho[index_chirho + 2].is_ascii_hexdigit()
            || bytes_chirho[index_chirho + 1].is_ascii_lowercase()
            || bytes_chirho[index_chirho + 2].is_ascii_lowercase()
        {
            return false;
        }
        let Some(high_chirho) =
            hex_nibble_chirho(bytes_chirho[index_chirho + 1].to_ascii_lowercase())
        else {
            return false;
        };
        let Some(low_chirho) =
            hex_nibble_chirho(bytes_chirho[index_chirho + 2].to_ascii_lowercase())
        else {
            return false;
        };
        let decoded_chirho = (high_chirho << 4) | low_chirho;
        if !(0x20..0x7f).contains(&decoded_chirho)
            || decoded_chirho.is_ascii_alphanumeric()
            || matches!(
                decoded_chirho,
                b'-' | b'.' | b'_' | b'~' | b'/' | b'?' | b'#' | b'\\'
            )
        {
            return false;
        }
        index_chirho += 3;
    }
    true
}

fn relay_wire_decode_error_chirho() -> RelayContractErrorChirho {
    RelayContractErrorChirho::new_chirho(
        RelayRefusalIdentityChirho::RelayWireDecodeRefusedChirho,
        "relay wire envelope could not be decoded exactly",
    )
}

fn relay_wire_too_large_error_chirho() -> RelayContractErrorChirho {
    RelayContractErrorChirho::new_chirho(
        RelayRefusalIdentityChirho::RelayWireTooLargeChirho,
        "relay wire envelope exceeds its fixed bound",
    )
}

fn outcome_class_bytes_chirho(outcome_chirho: RelayOutcomeClassChirho) -> &'static [u8] {
    match outcome_chirho {
        RelayOutcomeClassChirho::ServedResponseChirho => b"served-response-chirho",
        RelayOutcomeClassChirho::DoorRefusalChirho => b"door-refusal-chirho",
        RelayOutcomeClassChirho::RelayRefusalChirho => b"relay-refusal-chirho",
    }
}

fn decode_hex_32_chirho(value_chirho: &str) -> Option<[u8; 32]> {
    let bytes_chirho = decode_hex_chirho(value_chirho)?;
    bytes_chirho.try_into().ok()
}

fn decode_hex_chirho(value_chirho: &str) -> Option<Vec<u8>> {
    if !value_chirho.len().is_multiple_of(2) {
        return None;
    }
    value_chirho
        .as_bytes()
        .chunks_exact(2)
        .map(|pair_chirho| {
            let high_chirho = hex_nibble_chirho(pair_chirho[0])?;
            let low_chirho = hex_nibble_chirho(pair_chirho[1])?;
            Some((high_chirho << 4) | low_chirho)
        })
        .collect()
}

fn hex_nibble_chirho(byte_chirho: u8) -> Option<u8> {
    match byte_chirho {
        b'0'..=b'9' => Some(byte_chirho - b'0'),
        b'a'..=b'f' => Some(byte_chirho - b'a' + 10),
        _ => None,
    }
}

mod base64_bytes_chirho {
    use super::*;

    pub fn serialize<SerializerChirho>(
        bytes_chirho: &[u8],
        serializer_chirho: SerializerChirho,
    ) -> Result<SerializerChirho::Ok, SerializerChirho::Error>
    where
        SerializerChirho: serde::Serializer,
    {
        serializer_chirho.serialize_str(&STANDARD_NO_PAD.encode(bytes_chirho))
    }

    pub fn deserialize<'de, DeserializerChirho>(
        deserializer_chirho: DeserializerChirho,
    ) -> Result<Vec<u8>, DeserializerChirho::Error>
    where
        DeserializerChirho: serde::Deserializer<'de>,
    {
        let encoded_chirho = String::deserialize(deserializer_chirho)?;
        let bytes_chirho = STANDARD_NO_PAD
            .decode(&encoded_chirho)
            .map_err(serde::de::Error::custom)?;
        if STANDARD_NO_PAD.encode(&bytes_chirho) != encoded_chirho {
            return Err(serde::de::Error::custom(
                "relay body base64 is not canonical",
            ));
        }
        Ok(bytes_chirho)
    }
}

#[cfg(test)]
#[path = "protocol_chirho/tests_chirho.rs"]
mod tests_chirho;
