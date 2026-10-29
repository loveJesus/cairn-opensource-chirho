// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use crate::directory_chirho::valid_group_digest_chirho;
use crate::FixedGroupLeadershipViewChirho;
use anyhow::{bail, Result};
use cairn_write_relay_chirho::{
    PreparedServedWriteRelayAttemptChirho, PreparedServedWriteRelayRequestV1Chirho,
    RelayContractErrorChirho, RelayIngressScopeChirho, RelayRosterChirho,
    ServedLocalReadAuthorityPortChirho, ServedLocalReadAuthorityWitnessChirho,
    ServedWriteDispatchFutureChirho, ServedWriteDispatchInputChirho,
    ServedWriteDispatchOutcomeChirho, ServedWriteDispatchPortChirho, ServedWriteRelayFailureChirho,
    ServedWriteRelayPortChirho, ServedWriteRelayRequestInputChirho,
};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Clone, Default)]
pub struct LocalRelayAuthorityReadinessChirho {
    ready_chirho: Arc<AtomicBool>,
}

impl LocalRelayAuthorityReadinessChirho {
    pub fn new_chirho() -> Self {
        Self::default()
    }

    pub fn mark_ready_chirho(&self) {
        self.ready_chirho.store(true, Ordering::Release);
    }

    pub fn is_ready_chirho(&self) -> bool {
        self.ready_chirho.load(Ordering::Acquire)
    }
}

#[derive(Clone)]
pub struct LocalRelayDispatchPolicyChirho {
    relay_budget_millis_chirho: NonZeroU64,
    authority_readiness_chirho: LocalRelayAuthorityReadinessChirho,
}

impl LocalRelayDispatchPolicyChirho {
    pub fn new_chirho(
        relay_budget_millis_chirho: NonZeroU64,
        authority_readiness_chirho: LocalRelayAuthorityReadinessChirho,
    ) -> Self {
        Self {
            relay_budget_millis_chirho,
            authority_readiness_chirho,
        }
    }
}

pub trait RelayRequestSignerChirho: Send + Sync {
    fn node_id_chirho(&self) -> &str;
    fn sign_digest_chirho(&self, digest_chirho: &[u8; 32]) -> Result<String>;
}

pub struct ExistingKeyRelayRequestSignerChirho {
    root_chirho: PathBuf,
    expected_node_id_chirho: String,
}

impl ExistingKeyRelayRequestSignerChirho {
    pub fn new_chirho(root_chirho: &Path, expected_node_id_chirho: String) -> Result<Self> {
        let current_chirho =
            cairn_signer_chirho::signer_chirho::existing_keypair_pubkey_hex_chirho(root_chirho)?;
        if current_chirho != expected_node_id_chirho {
            bail!("relay request signer root does not match the configured node identity");
        }
        Ok(Self {
            root_chirho: root_chirho.to_path_buf(),
            expected_node_id_chirho,
        })
    }
}

impl RelayRequestSignerChirho for ExistingKeyRelayRequestSignerChirho {
    fn node_id_chirho(&self) -> &str {
        &self.expected_node_id_chirho
    }

    fn sign_digest_chirho(&self, digest_chirho: &[u8; 32]) -> Result<String> {
        let possession_chirho =
            cairn_signer_chirho::signer_chirho::sign_with_existing_key_possession_chirho(
                &self.root_chirho,
                digest_chirho,
            )?;
        if possession_chirho.key_id_chirho() != self.expected_node_id_chirho {
            bail!("relay request signer identity changed");
        }
        Ok(possession_chirho.into_signature_hex_chirho())
    }
}

pub struct HttpServedWriteDispatchPortChirho {
    local_node_id_chirho: String,
    group_digest_chirho: String,
    roster_chirho: Arc<RelayRosterChirho>,
    leadership_chirho: Arc<dyn FixedGroupLeadershipViewChirho>,
    signer_chirho: Arc<dyn RelayRequestSignerChirho>,
    relay_chirho: Arc<dyn ServedWriteRelayPortChirho>,
    local_policy_chirho: LocalRelayDispatchPolicyChirho,
}

impl HttpServedWriteDispatchPortChirho {
    pub fn new_chirho(
        local_node_id_chirho: String,
        group_digest_chirho: String,
        roster_chirho: Arc<RelayRosterChirho>,
        leadership_chirho: Arc<dyn FixedGroupLeadershipViewChirho>,
        signer_chirho: Arc<dyn RelayRequestSignerChirho>,
        relay_chirho: Arc<dyn ServedWriteRelayPortChirho>,
        local_policy_chirho: LocalRelayDispatchPolicyChirho,
    ) -> Result<Self> {
        if !valid_group_digest_chirho(&group_digest_chirho) {
            bail!("relay dispatcher group digest must be canonical lowercase BLAKE3 hex");
        }
        if !roster_chirho.contains_chirho(&local_node_id_chirho) {
            bail!("relay dispatcher local node must belong to the exact active roster");
        }
        if signer_chirho.node_id_chirho() != local_node_id_chirho {
            bail!("relay dispatcher signer and local roster identity differ");
        }
        Ok(Self {
            local_node_id_chirho,
            group_digest_chirho,
            roster_chirho,
            leadership_chirho,
            signer_chirho,
            relay_chirho,
            local_policy_chirho,
        })
    }

    fn current_local_read_authority_chirho(
        &self,
    ) -> Result<ServedLocalReadAuthorityWitnessChirho, ServedWriteRelayFailureChirho> {
        let leadership_chirho = self.leadership_chirho.current_leadership_chirho();
        let owner_chirho = leadership_chirho
            .leader_id_chirho
            .ok_or_else(RelayContractErrorChirho::owner_unknown_chirho)?;
        if owner_chirho.0 != self.local_node_id_chirho {
            return Err(RelayContractErrorChirho::local_authority_unavailable_chirho().into());
        }
        if !leadership_chirho.is_leader_chirho {
            return Err(RelayContractErrorChirho::owner_term_changed_chirho().into());
        }
        if !leadership_chirho.lease_valid_chirho {
            return Err(RelayContractErrorChirho::lease_expired_chirho().into());
        }
        if !self
            .local_policy_chirho
            .authority_readiness_chirho
            .is_ready_chirho()
        {
            return Err(RelayContractErrorChirho::local_authority_unavailable_chirho().into());
        }
        Ok(ServedLocalReadAuthorityWitnessChirho::new_chirho(
            self.local_node_id_chirho.clone(),
            leadership_chirho.term_chirho,
        ))
    }
}

impl ServedLocalReadAuthorityPortChirho for HttpServedWriteDispatchPortChirho {
    fn begin_local_read_chirho(
        &self,
    ) -> Result<ServedLocalReadAuthorityWitnessChirho, ServedWriteRelayFailureChirho> {
        self.current_local_read_authority_chirho()
    }

    fn confirm_local_read_chirho(
        &self,
        witness_chirho: &ServedLocalReadAuthorityWitnessChirho,
    ) -> Result<(), ServedWriteRelayFailureChirho> {
        let current_chirho = self.current_local_read_authority_chirho()?;
        if current_chirho != *witness_chirho {
            return Err(RelayContractErrorChirho::owner_term_changed_chirho().into());
        }
        Ok(())
    }
}

impl ServedWriteDispatchPortChirho for HttpServedWriteDispatchPortChirho {
    fn ingress_scope_chirho(&self) -> Option<RelayIngressScopeChirho> {
        Some(
            RelayIngressScopeChirho::new_chirho(
                self.local_node_id_chirho.clone(),
                self.group_digest_chirho.clone(),
                &self.roster_chirho,
            )
            .expect("dispatcher construction validated its fixed scope"),
        )
    }

    fn dispatch_chirho<'a>(
        &'a self,
        input_chirho: ServedWriteDispatchInputChirho,
    ) -> ServedWriteDispatchFutureChirho<'a> {
        Box::pin(async move {
            let leadership_chirho = self.leadership_chirho.current_leadership_chirho();
            let target_node_chirho = leadership_chirho
                .leader_id_chirho
                .ok_or_else(RelayContractErrorChirho::owner_unknown_chirho)?;
            if target_node_chirho.0 == self.local_node_id_chirho {
                if !leadership_chirho.is_leader_chirho {
                    return Err(RelayContractErrorChirho::owner_term_changed_chirho().into());
                }
                if !leadership_chirho.lease_valid_chirho {
                    return Err(RelayContractErrorChirho::lease_expired_chirho().into());
                }
                if !self
                    .local_policy_chirho
                    .authority_readiness_chirho
                    .is_ready_chirho()
                {
                    return Err(
                        RelayContractErrorChirho::local_authority_unavailable_chirho().into(),
                    );
                }
                return Ok(ServedWriteDispatchOutcomeChirho::ExecuteLocallyChirho);
            }

            if input_chirho.ingress_admission_chirho.is_none() {
                return Err(RelayContractErrorChirho::ingress_admission_invalid_chirho().into());
            }
            let prepared_chirho = PreparedServedWriteRelayRequestV1Chirho::new_chirho(
                ServedWriteRelayRequestInputChirho {
                    ingress_admission_chirho: input_chirho.ingress_admission_chirho,
                    origin_node_id_chirho: self.local_node_id_chirho.clone(),
                    target_node_id_chirho: target_node_chirho.0.clone(),
                    consistency_group_digest_chirho: self.group_digest_chirho.clone(),
                    expected_term_chirho: leadership_chirho.term_chirho,
                    caller_idempotency_key_chirho: input_chirho.caller_idempotency_key_chirho,
                    method_chirho: input_chirho.method_chirho,
                    uri_chirho: input_chirho.uri_chirho,
                    end_to_end_headers_chirho: input_chirho.end_to_end_headers_chirho,
                    body_chirho: input_chirho.body_chirho,
                    relay_budget_remaining_millis_chirho: self
                        .local_policy_chirho
                        .relay_budget_millis_chirho
                        .get(),
                },
            )?;
            let signature_chirho = self
                .signer_chirho
                .sign_digest_chirho(&prepared_chirho.signing_digest_chirho())
                .map_err(|_| RelayContractErrorChirho::request_signing_refused_chirho())?;
            let signed_chirho = prepared_chirho.into_signed_chirho(signature_chirho)?;
            let attempt_chirho = PreparedServedWriteRelayAttemptChirho::new_chirho(
                signed_chirho,
                &self.group_digest_chirho,
                &target_node_chirho.0,
                &self.roster_chirho,
            )?;
            let response_wire_chirho = self
                .relay_chirho
                .relay_one_hop_chirho(&attempt_chirho)
                .await?;
            let response_chirho = attempt_chirho
                .verify_response_chirho(&response_wire_chirho, &self.roster_chirho)?;
            Ok(ServedWriteDispatchOutcomeChirho::RelayedChirho(Box::new(
                response_chirho,
            )))
        })
    }
}

#[cfg(test)]
#[path = "dispatcher_chirho/tests_chirho.rs"]
mod tests_chirho;
