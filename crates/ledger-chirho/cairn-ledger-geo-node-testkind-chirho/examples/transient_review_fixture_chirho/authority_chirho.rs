// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Supplies a labelled local read-authority test double only for this owned latched fixture.

use super::ownership_chirho::LatchedRootChirho;
use cairn_write_relay_chirho::{
    RelayContractErrorChirho, ServedLocalReadAuthorityPortChirho,
    ServedLocalReadAuthorityWitnessChirho, ServedWriteDispatchFutureChirho,
    ServedWriteDispatchInputChirho, ServedWriteDispatchOutcomeChirho,
    ServedWriteDispatchPortChirho, ServedWriteRelayFailureChirho,
};
use std::sync::Arc;

pub(super) struct ReadDoubleChirho(Arc<LatchedRootChirho>);

impl ReadDoubleChirho {
    pub(super) fn for_owned_root_chirho(root_chirho: Arc<LatchedRootChirho>) -> Self {
        Self(root_chirho)
    }
}

impl ServedLocalReadAuthorityPortChirho for ReadDoubleChirho {
    fn begin_local_read_chirho(
        &self,
    ) -> Result<ServedLocalReadAuthorityWitnessChirho, ServedWriteRelayFailureChirho> {
        self.0.verify_chirho().map_err(|_error_chirho| {
            RelayContractErrorChirho::local_authority_unavailable_chirho()
        })?;
        Ok(ServedLocalReadAuthorityWitnessChirho::new_chirho(
            "component-owner-test-double-chirho".into(),
            7,
        ))
    }

    fn confirm_local_read_chirho(
        &self,
        witness_chirho: &ServedLocalReadAuthorityWitnessChirho,
    ) -> Result<(), ServedWriteRelayFailureChirho> {
        if witness_chirho.local_node_id_chirho() != "component-owner-test-double-chirho"
            || witness_chirho.term_chirho() != 7
            || self.0.verify_chirho().is_err()
        {
            return Err(RelayContractErrorChirho::owner_term_changed_chirho().into());
        }
        Ok(())
    }
}

pub(super) struct LocalDispatchChirho;

impl ServedWriteDispatchPortChirho for LocalDispatchChirho {
    fn dispatch_chirho<'a>(
        &'a self,
        _input_chirho: ServedWriteDispatchInputChirho,
    ) -> ServedWriteDispatchFutureChirho<'a> {
        Box::pin(async { Ok(ServedWriteDispatchOutcomeChirho::ExecuteLocallyChirho) })
    }
}
