// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Binds a source-admission policy to a signed request and a fixed trusted origin population.

use super::{valid_lower_hex_chirho, RelayRosterChirho, RELAY_DIGEST_HEX_BYTES_CHIRHO};
use crate::RelayContractErrorChirho;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum RelayIngressPolicyChirho {
    NetworkSourceV1Chirho,
}

/// An origin's signed assertion, not a client identity or a writer capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayIngressAdmissionChirho {
    policy_chirho: RelayIngressPolicyChirho,
    window_ms_chirho: u64,
    source_max_requests_chirho: u64,
    source_max_body_bytes_chirho: u64,
    ingress_max_requests_chirho: u64,
    ingress_max_body_bytes_chirho: u64,
}

impl RelayIngressAdmissionChirho {
    pub fn new_chirho(
        window_ms_chirho: u64,
        source_max_requests_chirho: u64,
        source_max_body_bytes_chirho: u64,
        ingress_max_requests_chirho: u64,
        ingress_max_body_bytes_chirho: u64,
    ) -> Result<Self, RelayContractErrorChirho> {
        let admission_chirho = Self {
            policy_chirho: RelayIngressPolicyChirho::NetworkSourceV1Chirho,
            window_ms_chirho,
            source_max_requests_chirho,
            source_max_body_bytes_chirho,
            ingress_max_requests_chirho,
            ingress_max_body_bytes_chirho,
        };
        admission_chirho.validate_chirho()?;
        Ok(admission_chirho)
    }

    pub(super) fn validate_chirho(&self) -> Result<(), RelayContractErrorChirho> {
        if self.window_ms_chirho == 0
            || self.source_max_requests_chirho == 0
            || self.source_max_body_bytes_chirho == 0
            || self.ingress_max_requests_chirho == 0
            || self.ingress_max_body_bytes_chirho == 0
        {
            return Err(RelayContractErrorChirho::ingress_admission_invalid_chirho());
        }
        Ok(())
    }

    pub fn permits_source_policy_chirho(&self, owner_chirho: &Self) -> bool {
        self.validate_chirho().is_ok()
            && self.policy_chirho == owner_chirho.policy_chirho
            && self.window_ms_chirho == owner_chirho.window_ms_chirho
            && self.source_max_requests_chirho <= owner_chirho.source_max_requests_chirho
            && self.source_max_body_bytes_chirho <= owner_chirho.source_max_body_bytes_chirho
    }

    pub fn ingress_max_requests_chirho(&self) -> u64 {
        self.ingress_max_requests_chirho
    }

    pub fn ingress_max_body_bytes_chirho(&self) -> u64 {
        self.ingress_max_body_bytes_chirho
    }

    pub(super) fn update_digest_chirho(&self, hasher_chirho: &mut blake3::Hasher) {
        super::update_digest_field_chirho(
            hasher_chirho,
            b"ingress-policy-chirho",
            b"network-source-v1-chirho",
        );
        for (label_chirho, value_chirho) in [
            (
                b"ingress-window-ms-chirho".as_slice(),
                self.window_ms_chirho,
            ),
            (
                b"source-max-requests-chirho",
                self.source_max_requests_chirho,
            ),
            (
                b"source-max-body-bytes-chirho",
                self.source_max_body_bytes_chirho,
            ),
            (
                b"ingress-max-requests-chirho",
                self.ingress_max_requests_chirho,
            ),
            (
                b"ingress-max-body-bytes-chirho",
                self.ingress_max_body_bytes_chirho,
            ),
        ] {
            super::update_digest_field_chirho(
                hasher_chirho,
                label_chirho,
                &value_chirho.to_le_bytes(),
            );
        }
    }
}

/// Process-local composition evidence; no request supplies or replaces this population.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayIngressScopeChirho {
    local_node_id_chirho: String,
    group_digest_chirho: String,
    roster_chirho: RelayRosterChirho,
}

impl RelayIngressScopeChirho {
    pub fn new_chirho(
        local_node_id_chirho: String,
        group_digest_chirho: String,
        roster_chirho: &RelayRosterChirho,
    ) -> Result<Self, RelayContractErrorChirho> {
        if !roster_chirho.contains_chirho(&local_node_id_chirho)
            || !valid_lower_hex_chirho(&group_digest_chirho, RELAY_DIGEST_HEX_BYTES_CHIRHO)
        {
            return Err(RelayContractErrorChirho::ingress_admission_invalid_chirho());
        }
        Ok(Self {
            local_node_id_chirho,
            group_digest_chirho,
            roster_chirho: roster_chirho.clone(),
        })
    }

    pub fn local_node_id_chirho(&self) -> &str {
        &self.local_node_id_chirho
    }

    pub fn consistency_group_digest_chirho(&self) -> &str {
        &self.group_digest_chirho
    }

    pub fn origin_count_chirho(&self) -> u64 {
        self.roster_chirho.members_chirho.len() as u64
    }

    pub fn accepts_request_chirho(
        &self,
        request_chirho: &super::VerifiedServedWriteRelayRequestChirho,
    ) -> bool {
        request_chirho.target_node_id_chirho() == self.local_node_id_chirho
            && request_chirho.consistency_group_digest_chirho() == self.group_digest_chirho
            && request_chirho.roster_digest_chirho == self.roster_chirho.digest_chirho
            && self
                .roster_chirho
                .contains_chirho(request_chirho.origin_node_id_chirho())
    }
}
