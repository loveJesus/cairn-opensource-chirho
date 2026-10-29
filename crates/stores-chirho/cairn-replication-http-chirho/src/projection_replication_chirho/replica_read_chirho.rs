// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::{read_verified_mounted_projection_chirho, ProjectionReplicaPullConfigChirho};
use anyhow::{bail, Context, Result};
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use cairn_ledger_model_chirho::record_chirho::HlcChirho;
use cairn_ledger_read_model_chirho::{
    canonical_account_net_projection_view_chirho,
    follower_chirho::{ProjectionWatermarkChirho, PublishedProjectionViewChirho},
};

/// Read-only projection port over the verified mounted replica state. It has no source journal,
/// writer head, refs, signer, or effect port, so every successful read is replica-observed.
pub struct ReplicaMountedProjectionReadPortChirho {
    config_chirho: ProjectionReplicaPullConfigChirho,
    replica_clock_ms_chirho: u64,
    max_lag_ms_chirho: u64,
}

/// The replica port's intermediate result has no Fresh variant. The root adapter is the only
/// place that can translate this verified replica observation into the shared serve outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicaMountedProjectionReadChirho {
    pub view_bytes_chirho: Vec<u8>,
    pub view_chirho: PublishedProjectionViewChirho,
    pub lag_ms_chirho: u64,
    pub max_lag_ms_chirho: u64,
}

/// The complete mutable-cut coordinate pinned by a replica serve process. Identity fields live in
/// the verified pull config; these fields distinguish every signed source advance, including two
/// receipts that happen to publish byte-identical balance views.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ReplicaProjectionMountCoordinateChirho {
    pub source_tail_seq_chirho: u64,
    pub source_tail_hlc_chirho: HlcChirho,
    pub source_tail_line_digest_chirho: String,
    pub view_digest_hex_chirho: String,
}

impl ReplicaMountedProjectionReadChirho {
    pub fn mount_coordinate_chirho(&self) -> ReplicaProjectionMountCoordinateChirho {
        ReplicaProjectionMountCoordinateChirho {
            source_tail_seq_chirho: self.view_chirho.watermark_chirho.source_seq_chirho,
            source_tail_hlc_chirho: self.view_chirho.watermark_chirho.source_hlc_chirho.clone(),
            source_tail_line_digest_chirho: self
                .view_chirho
                .watermark_chirho
                .signed_prefix_digest_chirho
                .0
                .clone(),
            view_digest_hex_chirho: self.view_chirho.state_digest_chirho.0.clone(),
        }
    }
}

impl ReplicaMountedProjectionReadPortChirho {
    pub fn new_chirho(
        config_chirho: ProjectionReplicaPullConfigChirho,
        replica_clock_ms_chirho: u64,
        max_lag_ms_chirho: u64,
    ) -> Self {
        Self {
            config_chirho,
            replica_clock_ms_chirho,
            max_lag_ms_chirho,
        }
    }

    pub fn read_published_projection_chirho(
        &self,
        projection_name_chirho: &str,
        requested_limit_chirho: u64,
    ) -> Result<ReplicaMountedProjectionReadChirho> {
        if projection_name_chirho != self.config_chirho.identity_chirho.projection_name_chirho {
            bail!("ReplicaProjectionNameRefusedChirho");
        }
        if requested_limit_chirho == 0 {
            bail!("ReplicaProjectionLimitRefusedChirho");
        }
        let (mount_chirho, view_chirho) =
            read_verified_mounted_projection_chirho(&self.config_chirho)?;
        let view_bytes_chirho = canonical_account_net_projection_view_chirho(&view_chirho)
            .context("ReplicaProjectionViewEncodeRefusedChirho")?;
        if blake3::hash(&view_bytes_chirho).to_hex().to_string()
            != mount_chirho.receipt_chirho.view_digest_hex_chirho
        {
            bail!("ReplicaProjectionViewDigestMismatchChirho");
        }
        let receipt_chirho = mount_chirho.receipt_chirho;
        let watermark_chirho = ProjectionWatermarkChirho {
            source_family_id_chirho: receipt_chirho.source_cluster_chirho,
            source_seq_chirho: receipt_chirho.source_tail_seq_chirho,
            source_hlc_chirho: receipt_chirho.source_tail_hlc_chirho.clone(),
            signed_prefix_digest_chirho: receipt_chirho.source_tail_line_digest_chirho.clone(),
        };
        let published_view_chirho = PublishedProjectionViewChirho {
            descriptor_ref_chirho: receipt_chirho.descriptor_digest_chirho.clone(),
            watermark_chirho,
            state_digest_chirho: DigestChirho(receipt_chirho.view_digest_hex_chirho),
        };
        let lag_ms_chirho = self
            .replica_clock_ms_chirho
            .saturating_sub(receipt_chirho.source_tail_hlc_chirho.physical_ms_chirho);
        Ok(ReplicaMountedProjectionReadChirho {
            view_bytes_chirho,
            view_chirho: published_view_chirho,
            lag_ms_chirho,
            max_lag_ms_chirho: self.max_lag_ms_chirho,
        })
    }

    /// Re-verify the currently installed mount and return its complete signed-cut coordinate.
    pub fn current_mount_coordinate_chirho(
        &self,
    ) -> Result<ReplicaProjectionMountCoordinateChirho> {
        let projection_name_chirho = self
            .config_chirho
            .identity_chirho
            .projection_name_chirho
            .clone();
        Ok(self
            .read_published_projection_chirho(&projection_name_chirho, 1)?
            .mount_coordinate_chirho())
    }
}
