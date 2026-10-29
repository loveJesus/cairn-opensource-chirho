// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Pins that the deposed-reader verification path requires a signed sink-cell birth term.
//!
//! `verify_bound_identity_public_chirho` is the held/deposed reader's entry point and had ZERO test
//! callers, so its `(expected_schema, require_birth_term, require_possession)` pairing was unpinned:
//! transposing its two adjacent same-typed bools compiled without a warning and passed every test in
//! this crate. This module closes that coverage hole. It pins BEHAVIOUR — a current-schema Bound
//! identity carrying no birth term must be refused, by name — not the argument list, so the type-level
//! fix can land without touching it.

use super::with_unbound_resident_fixture_chirho;
use crate::resident_authority_chirho::sink_term_lifecycle_chirho::create_or_recover_resident_sink_term_cell_at_term_for_test_chirho;
use crate::resident_ledger_identity_chirho::{
    canonical_bound_identity_chirho,
    canonical_current_v4_bound_identity_without_birth_term_for_test_chirho,
    verify_bound_identity_public_chirho, ResidentLedgerBoundIdentityVerificationRefusalChirho,
    ResidentLedgerCoordinateSourceChirho,
};
use crate::{FsLedgerStorageChirho, ResidentLedgerLocalPortsChirho};
use cairn_ledger_log_chirho::journal_chirho::{JournalPortsChirho, LedgerJournalChirho};
use cairn_ledger_log_chirho::ports_chirho::StoragePathChirho;
use cairn_seqlog_chirho::seqlog_chirho::named_lock_storage_key_chirho;
use cairn_writer_head_chirho::resident_writer_chirho::ResidentWriterReservationOutcomeChirho;
use cairn_writer_head_chirho::writer_head_chirho::WRITER_FENCE_LOCK_CHIRHO;

const PIN_BIRTH_TERM_CHIRHO: u64 = 3;

fn raw_journal_ports_for_pin_chirho(
    ports_chirho: ResidentLedgerLocalPortsChirho<'_>,
) -> JournalPortsChirho<'_> {
    JournalPortsChirho {
        storage_chirho: ports_chirho.storage_chirho,
        signer_chirho: ports_chirho.signer_chirho,
        clock_chirho: ports_chirho.clock_chirho,
        membership_chirho: ports_chirho.membership_chirho,
        kind_registry_chirho: ports_chirho.kind_registry_chirho,
        authority_chirho: ports_chirho.authority_chirho,
    }
}

#[test]
fn deposed_reader_refuses_a_current_bound_identity_missing_its_signed_birth_term_chirho() {
    with_unbound_resident_fixture_chirho(
        "deposed-reader-birth-term-pin",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let authority_storage_chirho =
                FsLedgerStorageChirho::open_existing_chirho(root_chirho).unwrap();
            let authority_snapshot_chirho = authority_storage_chirho
                .stable_namespace_snapshot_chirho()
                .unwrap();
            let storage_snapshot_chirho = ports_chirho
                .storage_chirho
                .stable_namespace_snapshot_chirho()
                .unwrap();
            let source_chirho = ResidentLedgerCoordinateSourceChirho {
                root_chirho,
                authority_root_snapshot_chirho: &authority_snapshot_chirho,
                group_chirho,
                storage_chirho: ports_chirho.storage_chirho,
                storage_snapshot_chirho: &storage_snapshot_chirho,
                identity_storage_namespace_chirho: ports_chirho
                    .storage_chirho
                    .namespace_root_chirho(),
                journal_path_chirho,
                cluster_id_chirho,
                opening_epoch_chirho: 0,
                local_node_chirho: node_chirho,
            };

            // A real genesis, actually created, so the genesis commitment cannot be the thing that
            // refuses below.
            let prepared_chirho = LedgerJournalChirho::prepare_genesis_chirho(
                raw_journal_ports_for_pin_chirho(ports_chirho),
                cluster_id_chirho.clone(),
                0,
            )
            .unwrap();
            drop(
                LedgerJournalChirho::create_prepared_chirho(
                    raw_journal_ports_for_pin_chirho(ports_chirho),
                    journal_path_chirho.clone(),
                    prepared_chirho.clone(),
                )
                .unwrap(),
            );

            let writer_lock_path_chirho = StoragePathChirho::new_chirho(
                named_lock_storage_key_chirho(WRITER_FENCE_LOCK_CHIRHO),
            );
            let mut writer_lock_chirho = authority_storage_chirho
                .provision_exclusive_lock_handle_chirho(&writer_lock_path_chirho)
                .unwrap();
            let writer_lock_guard_chirho = writer_lock_chirho.try_acquire_chirho().unwrap();
            let cell_proof_chirho =
                create_or_recover_resident_sink_term_cell_at_term_for_test_chirho(
                    group_chirho,
                    PIN_BIRTH_TERM_CHIRHO,
                    &writer_lock_guard_chirho,
                    ResidentWriterReservationOutcomeChirho::CreatedPendingChirho,
                )
                .unwrap();
            let identity_with_birth_term_chirho = canonical_bound_identity_chirho(
                source_chirho,
                prepared_chirho.canonical_line_chirho(),
                prepared_chirho.digest_chirho(),
                cell_proof_chirho,
            )
            .unwrap();
            drop(writer_lock_guard_chirho);
            drop(writer_lock_chirho);

            let identity_without_birth_term_chirho =
                canonical_current_v4_bound_identity_without_birth_term_for_test_chirho(
                    source_chirho,
                    prepared_chirho.canonical_line_chirho(),
                    prepared_chirho.digest_chirho(),
                )
                .unwrap();

            // POSITIVE CONTROL. The same coordinate, genesis, signer, and schema VERIFY when the
            // birth term is present. Without this, a refusal below would be attributable to any of
            // them, and a fixture refusable by two mechanisms proves neither.
            verify_bound_identity_public_chirho(&identity_with_birth_term_chirho, source_chirho)
                .expect(
                    "positive control: an otherwise-identical identity WITH its signed birth term \
                     must verify on the deposed-reader path. If this is the failing line, the \
                     fixture is broken or the path now demands something else -- fix the control \
                     before trusting the refusal assertion below",
                );

            // THE PIN.
            let refusal_chirho = verify_bound_identity_public_chirho(
                &identity_without_birth_term_chirho,
                source_chirho,
            )
            .err()
            .expect(
                "the deposed-reader path ACCEPTED a current-schema Bound identity carrying no signed \
                 sink-cell birth term. On correct code the birth-term requirement refuses it. This is \
                 the exact outcome produced by transposing require_birth_term_chirho with the \
                 adjacent require_possession_chirho -- two same-typed bools that compile in either \
                 order. MIGRATION: if those flags have since become types (a BirthTermPolicyChirho \
                 and a possession type), this arm should be retargeted at the typed call, not \
                 deleted -- the BEHAVIOUR it pins is unchanged",
            );

            // ASSERT THE REASON, not merely that something refused.
            assert_eq!(
                refusal_chirho.downcast_ref::<ResidentLedgerBoundIdentityVerificationRefusalChirho>(),
                Some(&ResidentLedgerBoundIdentityVerificationRefusalChirho::CurrentBirthTermMissingChirho),
                "refusal must be the MISSING BIRTH TERM by name. A different refusal means some other \
                 mechanism fired and the birth-term requirement itself is still unpinned; got: \
                 {refusal_chirho:#}"
            );

            // ASSERT THE NEGATIVE. Under the transposition require_possession_chirho flips ON, so a
            // possession or signature failure could refuse here and masquerade as this pin passing.
            let refusal_text_chirho = format!("{refusal_chirho:#}").to_lowercase();
            for forbidden_chirho in ["possession", "signature", "genesis", "schema"] {
                assert!(
                    !refusal_text_chirho.contains(forbidden_chirho),
                    "refusal mentions {forbidden_chirho:?}, so this fixture is refusable by a second \
                     mechanism and does not prove the birth-term requirement; got: {refusal_chirho:#}"
                );
            }
        },
    );
}
