// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Capability-attenuated local append-fence witness for tenant migration.
//!
//! This adapter observes an already-active handoff marker through
//! [`LocalAppendHandoffReadHandleChirho`]. It cannot install, restore, release, or append under that
//! marker. The durable migration coordinator must publish the attempt identity before activation,
//! verify the source tail afterward, and restore the exact attempt marker before resident exposure.
//!
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/authority-contract-chirho.md`.

use cairn_ledger_tenant_migration_chirho::{
    SourceAppendFenceWitnessChirho, TenantMigrationFenceIdentityChirho,
};
use cairn_writer_elector_chirho::{
    LocalAppendAuthorityRefusalChirho, LocalAppendHandoffReadGenerationChirho,
    LocalAppendHandoffReadHandleChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use std::fmt;

/// Read-only binding to one caller-supplied, already-active local handoff marker.
///
/// This type does not discover or establish that the supplied handle belongs to the running source
/// elector. It verifies only that handle's tenant group and marker lifetime. The durable coordinator
/// must supply the exact source handle from its one-writer composition before binding this witness.
pub struct LocalTenantMigrationFenceWitnessChirho {
    fence_identity_chirho: TenantMigrationFenceIdentityChirho,
    handoff_read_handle_chirho: LocalAppendHandoffReadHandleChirho,
    bound_generation_chirho: LocalAppendHandoffReadGenerationChirho,
}

impl LocalTenantMigrationFenceWitnessChirho {
    /// Bind one post-fence migration identity to the currently active exact-attempt generation.
    ///
    /// This function installs nothing. A different or absent marker refuses by identity, and any
    /// other authority refusal remains distinguishable from that mismatch.
    pub fn bind_active_chirho(
        fence_identity_chirho: TenantMigrationFenceIdentityChirho,
        handoff_read_handle_chirho: LocalAppendHandoffReadHandleChirho,
    ) -> Result<Self, LocalTenantMigrationFenceRefusalChirho> {
        let bound_generation_chirho = handoff_read_handle_chirho
            .try_acquire_handoff_read_chirho(fence_identity_chirho.attempt_chirho().digest_chirho())
            .map_err(map_handoff_refusal_chirho)?;
        let expected_group_chirho = ConsistencyGroupIdChirho::TenantChirho {
            tenant_id_chirho: fence_identity_chirho
                .attempt_chirho()
                .tenant_id_chirho()
                .to_owned(),
        };
        if bound_generation_chirho.consistency_group_chirho() != &expected_group_chirho {
            return Err(LocalTenantMigrationFenceRefusalChirho::SourceAuthorityGroupMismatchChirho);
        }
        Ok(Self {
            fence_identity_chirho,
            handoff_read_handle_chirho,
            bound_generation_chirho,
        })
    }

    fn generation_remains_exact_chirho(
        &self,
        observed_chirho: &LocalAppendHandoffReadGenerationChirho,
    ) -> bool {
        observed_chirho.handoff_digest_chirho()
            == self.bound_generation_chirho.handoff_digest_chirho()
            && observed_chirho.consistency_group_chirho()
                == self.bound_generation_chirho.consistency_group_chirho()
            && observed_chirho.node_id_chirho() == self.bound_generation_chirho.node_id_chirho()
            && observed_chirho.process_generation_chirho()
                == self.bound_generation_chirho.process_generation_chirho()
            && observed_chirho.published_raft_term_chirho()
                == self.bound_generation_chirho.published_raft_term_chirho()
            && observed_chirho.handoff_activation_generation_chirho()
                == self
                    .bound_generation_chirho
                    .handoff_activation_generation_chirho()
    }
}

impl SourceAppendFenceWitnessChirho for LocalTenantMigrationFenceWitnessChirho {
    fn fence_identity_chirho(&self) -> &TenantMigrationFenceIdentityChirho {
        &self.fence_identity_chirho
    }

    fn remains_active_chirho(&self) -> bool {
        self.handoff_read_handle_chirho
            .try_acquire_handoff_read_chirho(
                self.fence_identity_chirho.attempt_chirho().digest_chirho(),
            )
            .is_ok_and(|observed_chirho| self.generation_remains_exact_chirho(&observed_chirho))
    }
}

impl fmt::Debug for LocalTenantMigrationFenceWitnessChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho
            .debug_struct("LocalTenantMigrationFenceWitnessChirho")
            .field("fence_identity_chirho", &self.fence_identity_chirho)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants carry the Chirho suffix"
)]
pub enum LocalTenantMigrationFenceRefusalChirho {
    AttemptMarkerMismatchChirho,
    SourceAuthorityGroupMismatchChirho,
    HandoffReadRefusedChirho(LocalAppendAuthorityRefusalChirho),
}

impl fmt::Display for LocalTenantMigrationFenceRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter_chirho, "{self:?}")
    }
}

impl std::error::Error for LocalTenantMigrationFenceRefusalChirho {}

fn map_handoff_refusal_chirho(
    refusal_chirho: LocalAppendAuthorityRefusalChirho,
) -> LocalTenantMigrationFenceRefusalChirho {
    match refusal_chirho {
        LocalAppendAuthorityRefusalChirho::HandoffIdentityMismatchChirho => {
            LocalTenantMigrationFenceRefusalChirho::AttemptMarkerMismatchChirho
        }
        other_chirho => {
            LocalTenantMigrationFenceRefusalChirho::HandoffReadRefusedChirho(other_chirho)
        }
    }
}

#[cfg(test)]
#[path = "tests_chirho.rs"]
mod tests_chirho;
