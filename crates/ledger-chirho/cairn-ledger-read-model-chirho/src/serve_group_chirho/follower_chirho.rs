// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Fail-closed follower-read classification over already verified signed-prefix views.

use crate::descriptor_chirho::{
    validate_digest_chirho, ProjectionReadPolicyChirho, VerifiedProjectionDescriptorChirho,
};
use cairn_ledger_model_chirho::{ids_chirho::DigestChirho, record_chirho::HlcChirho};

/// The signed source prefix from which a published projection was derived.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProjectionWatermarkChirho {
    pub source_family_id_chirho: String,
    pub source_seq_chirho: u64,
    pub source_hlc_chirho: HlcChirho,
    pub signed_prefix_digest_chirho: DigestChirho,
}

/// One atomically published complete projection view.
///
/// Rebuild scratch state has a distinct internal representation and cannot be passed here. This
/// view remains derived/non-authoritative even when fresh; money consumers independently verify its
/// derivation against the signed ledger before using it as evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedProjectionViewChirho {
    pub descriptor_ref_chirho: DigestChirho,
    pub watermark_chirho: ProjectionWatermarkChirho,
    pub state_digest_chirho: DigestChirho,
}

/// Latest source head after the owning adapter has verified its signature, chain, and identity.
/// This DTO is evidence input, not an independently forge-proof authority token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedProjectionSourceHeadChirho {
    pub source_family_id_chirho: String,
    pub source_seq_chirho: u64,
    pub source_hlc_chirho: HlcChirho,
    pub signed_prefix_digest_chirho: DigestChirho,
}

/// One stable read cut after the owning adapter verified that `view_prefix_chirho` is the exact
/// signed-chain ancestor named by the published view and that `current_head_chirho` is the current
/// verified head of the same source family.
///
/// This is evidence input rather than an authority token. The pure classifier exact-matches the
/// published watermark to the verified ancestor; the production adapter owns chain verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedProjectionReadCutChirho {
    pub descriptor_ref_chirho: DigestChirho,
    pub view_prefix_chirho: ProjectionWatermarkChirho,
    pub current_head_chirho: VerifiedProjectionSourceHeadChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FollowerReadRefusalChirho {
    SourceFamilyMismatchChirho,
    InvalidDigestEvidenceChirho,
    DescriptorIdentityMismatchChirho,
    ViewWatermarkEvidenceMismatchChirho,
    WatermarkBeyondVerifiedPrefixChirho,
    WatermarkHlcBeyondVerifiedHeadChirho,
    EqualSeqHeadMismatchChirho,
    /// A write-and-serve host observed a published cut behind its own durable journal cut.
    EffectCutBehindChirho,
    StaleBeyondContractChirho {
        lag_ms_chirho: u64,
        max_lag_ms_chirho: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProjectionReadOutcomeChirho {
    #[non_exhaustive]
    FreshChirho {
        view_chirho: PublishedProjectionViewChirho,
        lag_ms_chirho: u64,
    },
    DegradedChirho {
        view_chirho: PublishedProjectionViewChirho,
        lag_ms_chirho: u64,
        max_lag_ms_chirho: u64,
    },
    RefusedChirho(FollowerReadRefusalChirho),
}

impl ProjectionReadOutcomeChirho {
    /// The defining crate's mint for owner-verified fresh reads. External crates cannot
    /// construct the non-exhaustive FreshChirho variant directly.
    pub fn fresh_from_verified_cut_chirho(
        _cut_chirho: &VerifiedProjectionReadCutChirho,
        view_chirho: PublishedProjectionViewChirho,
        lag_ms_chirho: u64,
    ) -> Self {
        Self::FreshChirho {
            view_chirho,
            lag_ms_chirho,
        }
    }
}

/// Classify a read without consulting a clock or store. The caller supplies a complete published
/// view and the verified current source head from one stable observation cut.
/// See `spec-chirho/workflows-chirho/projection-chirho/cf4-read-model-foundation-chirho.md`.
pub fn classify_follower_read_chirho(
    view_chirho: &PublishedProjectionViewChirho,
    verified_cut_chirho: &VerifiedProjectionReadCutChirho,
    verified_descriptor_chirho: &VerifiedProjectionDescriptorChirho,
) -> ProjectionReadOutcomeChirho {
    let verified_head_chirho = &verified_cut_chirho.current_head_chirho;
    let descriptor_chirho = verified_descriptor_chirho.descriptor_chirho();
    let staleness_chirho = &descriptor_chirho.staleness_contract_chirho;
    if !descriptor_chirho
        .source_families_chirho
        .iter()
        .any(|source_chirho| {
            source_chirho.family_id_chirho == view_chirho.watermark_chirho.source_family_id_chirho
        })
        || view_chirho.watermark_chirho.source_family_id_chirho
            != verified_head_chirho.source_family_id_chirho
    {
        return ProjectionReadOutcomeChirho::RefusedChirho(
            FollowerReadRefusalChirho::SourceFamilyMismatchChirho,
        );
    }
    if validate_digest_chirho("projection state", &view_chirho.state_digest_chirho).is_err()
        || validate_digest_chirho("projection descriptor", &view_chirho.descriptor_ref_chirho)
            .is_err()
        || validate_digest_chirho(
            "verified projection descriptor",
            &verified_cut_chirho.descriptor_ref_chirho,
        )
        .is_err()
        || validate_digest_chirho(
            "projection watermark",
            &view_chirho.watermark_chirho.signed_prefix_digest_chirho,
        )
        .is_err()
        || validate_digest_chirho(
            "verified source head",
            &verified_head_chirho.signed_prefix_digest_chirho,
        )
        .is_err()
    {
        return ProjectionReadOutcomeChirho::RefusedChirho(
            FollowerReadRefusalChirho::InvalidDigestEvidenceChirho,
        );
    }
    if view_chirho.descriptor_ref_chirho != verified_cut_chirho.descriptor_ref_chirho
        || view_chirho.descriptor_ref_chirho != *verified_descriptor_chirho.digest_chirho()
    {
        return ProjectionReadOutcomeChirho::RefusedChirho(
            FollowerReadRefusalChirho::DescriptorIdentityMismatchChirho,
        );
    }
    if view_chirho.watermark_chirho != verified_cut_chirho.view_prefix_chirho {
        return ProjectionReadOutcomeChirho::RefusedChirho(
            FollowerReadRefusalChirho::ViewWatermarkEvidenceMismatchChirho,
        );
    }
    if view_chirho.watermark_chirho.source_seq_chirho > verified_head_chirho.source_seq_chirho {
        return ProjectionReadOutcomeChirho::RefusedChirho(
            FollowerReadRefusalChirho::WatermarkBeyondVerifiedPrefixChirho,
        );
    }
    if view_chirho.watermark_chirho.source_hlc_chirho > verified_head_chirho.source_hlc_chirho {
        return ProjectionReadOutcomeChirho::RefusedChirho(
            FollowerReadRefusalChirho::WatermarkHlcBeyondVerifiedHeadChirho,
        );
    }
    if view_chirho.watermark_chirho.source_seq_chirho == verified_head_chirho.source_seq_chirho
        && (view_chirho.watermark_chirho.signed_prefix_digest_chirho
            != verified_head_chirho.signed_prefix_digest_chirho
            || view_chirho.watermark_chirho.source_hlc_chirho
                != verified_head_chirho.source_hlc_chirho)
    {
        return ProjectionReadOutcomeChirho::RefusedChirho(
            FollowerReadRefusalChirho::EqualSeqHeadMismatchChirho,
        );
    }

    let lag_ms_chirho = verified_head_chirho
        .source_hlc_chirho
        .physical_ms_chirho
        .saturating_sub(
            view_chirho
                .watermark_chirho
                .source_hlc_chirho
                .physical_ms_chirho,
        );
    if lag_ms_chirho <= staleness_chirho.max_owner_hlc_lag_ms_chirho {
        return ProjectionReadOutcomeChirho::fresh_from_verified_cut_chirho(
            verified_cut_chirho,
            view_chirho.clone(),
            lag_ms_chirho,
        );
    }
    match staleness_chirho.read_policy_chirho {
        ProjectionReadPolicyChirho::RefuseWhenStaleChirho => {
            ProjectionReadOutcomeChirho::RefusedChirho(
                FollowerReadRefusalChirho::StaleBeyondContractChirho {
                    lag_ms_chirho,
                    max_lag_ms_chirho: staleness_chirho.max_owner_hlc_lag_ms_chirho,
                },
            )
        }
        ProjectionReadPolicyChirho::ServeDegradedWithLagChirho => {
            ProjectionReadOutcomeChirho::DegradedChirho {
                view_chirho: view_chirho.clone(),
                lag_ms_chirho,
                max_lag_ms_chirho: staleness_chirho.max_owner_hlc_lag_ms_chirho,
            }
        }
    }
}
