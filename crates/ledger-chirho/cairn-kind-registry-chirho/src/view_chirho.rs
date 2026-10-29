// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The PRODUCTION `KindRegistryViewChirho`: admission's registry view served from the VERIFIED
//! projection — Current for a kind's current ref, Superseded for any ref an amend has superseded
//! (the policy-downgrade refusal's source of truth), Unknown otherwise. Composition roots build it
//! from `load_verified_registry_chirho`; admission keeps consuming the trait unchanged.

use crate::chain_chirho::{KindProjectionChirho, VerifiedRegistryChirho};
use crate::record_chirho::MintAuthorityRecordChirho;
use cairn_ledger_log_chirho::admission_chirho::{
    CurrentContinuationPolicyChirho, IdempotencyWindowPolicyViewChirho, KindPolicyViewChirho,
    KindRegistryViewChirho, KindResolutionChirho, MintAuthorityPolicyChirho,
    RecordedRetentionWindowChirho,
};
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, AssetKindRefChirho};

/// Map the registry's wire mint-authority to admission's view enum (the one mapping site).
fn mint_authority_view_chirho(
    record_chirho: &MintAuthorityRecordChirho,
) -> MintAuthorityPolicyChirho {
    match record_chirho {
        MintAuthorityRecordChirho::ProviderReceiptChirho => {
            MintAuthorityPolicyChirho::ProviderReceiptChirho
        }
        MintAuthorityRecordChirho::PlatformPolicyChirho { max_supply_chirho } => {
            MintAuthorityPolicyChirho::PlatformPolicyChirho {
                max_supply_chirho: *max_supply_chirho,
            }
        }
        MintAuthorityRecordChirho::ClosedChirho => MintAuthorityPolicyChirho::ClosedChirho,
    }
}

fn current_policy_view_chirho(
    kind_id_chirho: &AssetKindIdChirho,
    projection_chirho: &KindProjectionChirho,
) -> KindPolicyViewChirho {
    KindPolicyViewChirho {
        kind_id_chirho: kind_id_chirho.clone(),
        mint_authority_chirho: mint_authority_view_chirho(
            &projection_chirho
                .current_policy_chirho
                .mint_authority_chirho,
        ),
        rounding_chirho: projection_chirho.current_policy_chirho.rounding_chirho,
        settlement_owner_chirho: projection_chirho
            .current_policy_chirho
            .settlement_owner_chirho
            .clone(),
        idempotency_window_chirho: projection_chirho
            .current_policy_chirho
            .idempotency_window_chirho
            .map(|window_chirho| IdempotencyWindowPolicyViewChirho {
                idempotency_horizon_ms_chirho: window_chirho.idempotency_horizon_ms_chirho,
                retry_finality_horizon_ms_chirho: window_chirho.retry_finality_horizon_ms_chirho,
            }),
    }
}

impl KindRegistryViewChirho for VerifiedRegistryChirho {
    fn resolve_chirho(&self, policy_ref_chirho: &AssetKindRefChirho) -> KindResolutionChirho {
        for (kind_id_chirho, projection_chirho) in &self.kinds_chirho {
            if projection_chirho.current_ref_chirho == *policy_ref_chirho {
                return KindResolutionChirho::CurrentChirho(current_policy_view_chirho(
                    kind_id_chirho,
                    projection_chirho,
                ));
            }
            if projection_chirho
                .superseded_refs_chirho
                .contains(policy_ref_chirho)
            {
                return KindResolutionChirho::SupersededChirho;
            }
        }
        KindResolutionChirho::UnknownChirho
    }

    fn resolve_recorded_ref_retention_window_chirho(
        &self,
        policy_ref_chirho: &AssetKindRefChirho,
    ) -> RecordedRetentionWindowChirho {
        for projection_chirho in self.kinds_chirho.values() {
            let belongs_to_kind_chirho = projection_chirho.current_ref_chirho == *policy_ref_chirho
                || projection_chirho
                    .superseded_refs_chirho
                    .contains(policy_ref_chirho);
            if belongs_to_kind_chirho {
                return projection_chirho
                    .current_policy_chirho
                    .idempotency_window_chirho
                    .map(|window_chirho| {
                        RecordedRetentionWindowChirho::BoundedChirho(
                            IdempotencyWindowPolicyViewChirho {
                                idempotency_horizon_ms_chirho: window_chirho
                                    .idempotency_horizon_ms_chirho,
                                retry_finality_horizon_ms_chirho: window_chirho
                                    .retry_finality_horizon_ms_chirho,
                            },
                        )
                    })
                    .unwrap_or(RecordedRetentionWindowChirho::RetainIndefinitelyChirho);
            }
        }
        RecordedRetentionWindowChirho::RetainIndefinitelyChirho
    }

    fn resolve_current_continuation_by_kind_chirho(
        &self,
        kind_id_chirho: &AssetKindIdChirho,
    ) -> Option<CurrentContinuationPolicyChirho> {
        let projection_chirho = self.kinds_chirho.get(kind_id_chirho)?;
        Some(CurrentContinuationPolicyChirho {
            kind_policy_ref_chirho: projection_chirho.current_ref_chirho.clone(),
            policy_chirho: current_policy_view_chirho(kind_id_chirho, projection_chirho),
        })
    }
}
