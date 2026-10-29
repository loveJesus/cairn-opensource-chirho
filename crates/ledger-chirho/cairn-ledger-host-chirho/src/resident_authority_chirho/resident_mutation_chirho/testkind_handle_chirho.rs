// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Test-kind-only, phase-bounded final-sink witness handle.

use super::*;
#[derive(Clone)]
pub struct ResidentTestkindLossWitnessHandleChirho {
    command_sender_chirho: SyncSender<ResidentEffectJournalCommandChirho>,
}

impl ResidentTestkindLossWitnessHandleChirho {
    fn request_chirho(
        &self,
        phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
        command_chirho: impl FnOnce(
            ResidentTestkindLossWitnessPhaseChirho,
            SyncSender<
                std::result::Result<
                    ResidentTestkindLossWitnessOutcomeChirho,
                    ResidentTestkindLossWitnessRefusalChirho,
                >,
            >,
        ) -> ResidentEffectJournalCommandChirho,
    ) -> std::result::Result<
        ResidentTestkindLossWitnessOutcomeChirho,
        ResidentTestkindLossWitnessRefusalChirho,
    > {
        let (reply_sender_chirho, reply_receiver_chirho) = sync_channel(1);
        match self
            .command_sender_chirho
            .try_send(command_chirho(phase_chirho, reply_sender_chirho))
        {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                return Err(ResidentTestkindLossWitnessRefusalChirho::ActorUnavailableChirho);
            }
        }
        reply_receiver_chirho.recv().unwrap_or(Err(
            ResidentTestkindLossWitnessRefusalChirho::ActorUnavailableChirho,
        ))
    }

    pub fn execute_current_chirho(
        &self,
        phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    ) -> std::result::Result<
        ResidentTestkindLossWitnessOutcomeChirho,
        ResidentTestkindLossWitnessRefusalChirho,
    > {
        self.request_chirho(phase_chirho, |phase_chirho, reply_chirho| {
            ResidentEffectJournalCommandChirho::TestkindLossWitnessCurrentChirho {
                phase_chirho,
                reply_chirho,
            }
        })
    }

    /// Commit the SECOND post-adoption observation, so the canary window has a measurable span.
    ///
    /// Distinct from `execute_current_chirho` by role, which is what makes it a fresh append key
    /// rather than a duplicate of the first witness in the same phase.
    pub fn execute_sustained_chirho(
        &self,
        phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    ) -> std::result::Result<
        ResidentTestkindLossWitnessOutcomeChirho,
        ResidentTestkindLossWitnessRefusalChirho,
    > {
        self.request_chirho(phase_chirho, |phase_chirho, reply_chirho| {
            ResidentEffectJournalCommandChirho::TestkindLossWitnessSustainedChirho {
                phase_chirho,
                reply_chirho,
            }
        })
    }

    pub fn execute_deposed_sink_chirho(
        &self,
        phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    ) -> std::result::Result<
        ResidentTestkindLossWitnessOutcomeChirho,
        ResidentTestkindLossWitnessRefusalChirho,
    > {
        self.request_chirho(phase_chirho, |phase_chirho, reply_chirho| {
            ResidentEffectJournalCommandChirho::TestkindLossWitnessDeposedSinkChirho {
                phase_chirho,
                reply_chirho,
            }
        })
    }
}

impl ResidentEffectJournalHandleChirho {
    /// Derive the fixed test-kind loss witness without exposing the broader journal handle.
    ///
    /// Marker-less production actors have no derivation path. The actor independently retained a
    /// plan derived from this effective config and its verified kind registry at startup.
    pub fn testkind_loss_witness_handle_chirho(
        &self,
    ) -> std::result::Result<
        ResidentTestkindLossWitnessHandleChirho,
        ResidentTestkindLossWitnessRefusalChirho,
    > {
        if self.ledger_config_chirho.test_kind_chirho.is_none() {
            return Err(ResidentTestkindLossWitnessRefusalChirho::TestKindConfigRequiredChirho);
        }
        let command_sender_chirho = self
            .command_sender_chirho
            .as_ref()
            .ok_or(ResidentTestkindLossWitnessRefusalChirho::ActorUnavailableChirho)?
            .clone();
        Ok(ResidentTestkindLossWitnessHandleChirho {
            command_sender_chirho,
        })
    }
}
