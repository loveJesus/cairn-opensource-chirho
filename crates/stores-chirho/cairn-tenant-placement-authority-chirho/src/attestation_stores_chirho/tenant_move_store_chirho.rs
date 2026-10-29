// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! A tenant-root move as an append-only log of signed stages, with the stage DERIVED by replay.
//!
//! CF8 clause 4 wants the move CRASH/RETRY-SAFE, and that word decides the design. A mover that
//! crashes cannot know whether its last stage record landed, so it must re-drive — and the only thing
//! that can answer "did it" is the log. So nothing stores "how far did I get": the stage is replayed,
//! and an exact signed-record retry succeeds without appending twice. A different signed record at
//! an already occupied sequence refuses under its own identity.
//!
//! **The writer is DERIVED, never stored.** `current_writer_chirho` reads it off the replayed stage
//! through `writer_at_chirho`, so there is no field that could disagree with the sequence. That is what
//! makes "preserves one writer" a property of the log rather than a promise about a variable.
//!
//! **Ordering is applied through the RULE before anything is appended.** A handoff offered before
//! custody, or a retirement before handoff, is refused here with the rule's own identity — so the log
//! can never contain a sequence that replay would later choke on, and an operator is told which of the
//! two opposite mistakes they made.
//!
//! This module cannot sign. It verifies, and refuses. A store that could author a stage record could
//! author a retirement, which erases a key.

use super::move_control_store_chirho::{
    load_bounded_move_control_records_chirho, store_verified_move_control_record_chirho,
    MoveControlStoreRefusalChirho,
};
use cairn_seqlog_chirho::seqlog_chirho;
use cairn_tenant_chirho::move_chirho::move_attestation_chirho::{
    verify_move_control_record_chirho, MoveAuthorityPortChirho, MoveStageAttestationChirho,
    VerifiedMoveControlRecordChirho, VerifiedMoveStageChirho,
};
use cairn_tenant_chirho::move_chirho::move_stages_chirho::{
    advance_stage_chirho, writer_at_chirho, MoveAdvanceRefusalChirho, MoveStageChirho,
    MoveWriterChirho,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub const TENANT_MOVE_STAGE_LOG_CHIRHO: &str = "tenant-root-move-stages-chirho.jsonl";
pub const TENANT_MOVE_STAGE_LOG_MAX_BYTES_CHIRHO: u64 = 4 * 1024 * 1024;
const TENANT_MOVE_STAGE_LOCK_CHIRHO: &str = "tenant-root-move-stages-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TenantMoveStoreRefusalChirho {
    StoreUnavailableChirho,
    StoreIdentityUnstableChirho,
    DecodeChirho {
        line_chirho: u64,
    },
    NotVerifiedChirho,
    /// A stale sequence with no identical signed record at that coordinate.
    ReplayedStageSeqChirho {
        move_id_chirho: String,
        highest_recorded_chirho: u64,
        offered_chirho: u64,
    },
    /// One sequence coordinate names different signed records. An exact retry is an `Ok` no-op; this
    /// identity is reserved for a conflicting authorisation or a duplicate already on disk.
    ConflictingStageSeqChirho {
        move_id_chirho: String,
        stage_seq_chirho: u64,
    },
    /// Every row for one move must name the same source and target roots.
    MoveCoordinatesChangedChirho {
        move_id_chirho: String,
    },
    /// The stage does not follow the one the log produces. Carries the RULE's own refusal, so
    /// handoff-before-custody and retirement-before-handoff keep their distinct identities.
    OrderingChirho {
        refusal_chirho: MoveAdvanceRefusalChirho,
    },
    /// Fixed five-stage grammar uses the next coordinate, not merely any higher number.
    StageSeqNotNextChirho {
        expected_chirho: u64,
        offered_chirho: u64,
    },
    /// Typed control-namespace publication, resolution, or bounded-set verification refused.
    ControlRecordChirho {
        refusal_chirho: MoveControlStoreRefusalChirho,
    },
    /// Only a complete handoff/terminal pair may be pre-stored, and only after custody placement.
    PrestoreRequiresCustodyPlacedChirho,
    PrestoreNeedsHandoffAndTerminalChirho,
    PostHandoffRecordCoordinatesChangedChirho,
    PostHandoffRecordSequenceMismatchChirho {
        handoff_chirho: u64,
        terminal_chirho: u64,
    },
    PostHandoffRecordPermitMismatchChirho,
    /// A signed row exists in the log but its content-addressed control record is absent.
    LoggedControlRecordMissingChirho {
        logged_chirho: usize,
        stored_chirho: usize,
    },
    /// The control shard contains a valid signed record outside the stage grammar's allowed set.
    UnexpectedControlRecordChirho {
        allowed_chirho: usize,
        stored_chirho: usize,
    },
    /// Replay found a bounded valid control set that is not one complete stage-grammar shape.
    ControlRecordGrammarMismatchChirho {
        logged_chirho: usize,
        stored_chirho: usize,
    },
    /// The exact control set changed between the pre-write check and post-write verification.
    ControlRecordSetChangedDuringWriteChirho {
        expected_chirho: usize,
        found_chirho: usize,
    },
    /// Handoff/retirement may append only records already present in the frozen permit set.
    RequiredPrestoredControlRecordMissingChirho {
        logged_chirho: usize,
        stored_chirho: usize,
    },
    /// Backstop if address-from-canonical-bytes ever stops holding upstream of this comparison.
    /// Under the current content-addressed writer and reader this is invariant-only, not an ordinary
    /// operator disposition.
    ControlRecordAddressInvariantBackstopChirho {
        logged_chirho: usize,
        stored_chirho: usize,
    },
    /// No stage on record for this move at all.
    NoSuchMoveChirho {
        move_id_chirho: String,
    },
}

#[derive(Clone, Debug)]
struct VerifiedStoredMoveStageChirho {
    record_chirho: MoveStageAttestationChirho,
    verified_chirho: VerifiedMoveStageChirho,
    record_digest_chirho: String,
}

fn log_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join(TENANT_MOVE_STAGE_LOG_CHIRHO)
}

fn read_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<MoveStageAttestationChirho>, TenantMoveStoreRefusalChirho> {
    let path_chirho = log_path_chirho(root_chirho);
    // THREE cases, not two. `Path::exists()` reports false for a missing file AND for a path whose
    // metadata call fails, so the old pre-check read an UNREADABLE log as "no stage was ever
    // recorded" and returned an empty history — a failure signal converted into an absence. The
    // read itself distinguishes all three, and doing it here also closes the exists()/open race.
    let bytes_chirho = match cairn_durable_chirho::read_identity_stable_bounded_regular_file_chirho(
        &path_chirho,
        TENANT_MOVE_STAGE_LOG_MAX_BYTES_CHIRHO,
    ) {
        Ok(bytes_chirho) => bytes_chirho,
        // ABSENT: no stage has ever been recorded at this root. An empty history is the truth.
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Vec::new());
        }
        // PRESENT, but not one identity-stable bounded regular file.
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::InvalidData => {
            return Err(TenantMoveStoreRefusalChirho::StoreIdentityUnstableChirho);
        }
        // PRESENT but unreadable — permissions, IO, anything else. Fail closed.
        Err(_error_chirho) => return Err(TenantMoveStoreRefusalChirho::StoreUnavailableChirho),
    };
    let text_chirho = String::from_utf8_lossy(&bytes_chirho);
    let mut records_chirho = Vec::new();
    for (index_chirho, line_chirho) in text_chirho.lines().enumerate() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        records_chirho.push(serde_json::from_str(line_chirho).map_err(|_error_chirho| {
            TenantMoveStoreRefusalChirho::DecodeChirho {
                line_chirho: index_chirho as u64 + 1,
            }
        })?);
    }
    Ok(records_chirho)
}

fn verified_records_in_seq_order_chirho(
    root_chirho: &Path,
    move_id_chirho: &str,
    authority_chirho: &dyn MoveAuthorityPortChirho,
) -> Result<Vec<VerifiedStoredMoveStageChirho>, TenantMoveStoreRefusalChirho> {
    // Deliberately derive the high-water from this same retained-row read. There is no stage-head
    // sidecar, so "head says N while row N is absent/unreadable" cannot arise. If a future O(1)
    // sidecar is added, it must stay advisory behind-never-ahead and gain an explicit
    // head-ahead/row-missing test. The malformed-row arm remains green and does not guard that new
    // two-source disagreement.
    let mut records_chirho = read_records_chirho(root_chirho)?
        .into_iter()
        .map(|record_chirho| {
            // Authenticate BEFORE filtering. The claimed id is safe to pass only because the
            // recomputed intent digest and authority signature bind it before it is observed here.
            let claimed_move_id_chirho = record_chirho.intent_chirho.move_id_chirho.clone();
            let verified_control_chirho = verify_move_control_record_chirho(
                &record_chirho,
                authority_chirho,
                &claimed_move_id_chirho,
            )
            .map_err(|_error_chirho| TenantMoveStoreRefusalChirho::NotVerifiedChirho)?;
            Ok(VerifiedStoredMoveStageChirho {
                record_chirho,
                verified_chirho: verified_control_chirho.verified_stage_chirho().clone(),
                record_digest_chirho: verified_control_chirho.record_digest_chirho().to_string(),
            })
        })
        .collect::<Result<Vec<_>, TenantMoveStoreRefusalChirho>>()?;
    records_chirho
        .retain(|record_chirho| record_chirho.verified_chirho.move_id_chirho() == move_id_chirho);
    // Sequence order, not append order: the sequence is what the authority signed, and a log whose
    // append order disagreed would replay a handoff before the custody that must precede it.
    records_chirho.sort_by_key(|record_chirho| record_chirho.verified_chirho.stage_seq_chirho());

    if let Some(first_chirho) = records_chirho.first() {
        let source_root_chirho = first_chirho.verified_chirho.source_root_chirho();
        let target_root_chirho = first_chirho.verified_chirho.target_root_chirho();
        if records_chirho.iter().any(|record_chirho| {
            record_chirho.verified_chirho.source_root_chirho() != source_root_chirho
                || record_chirho.verified_chirho.target_root_chirho() != target_root_chirho
        }) {
            return Err(TenantMoveStoreRefusalChirho::MoveCoordinatesChangedChirho {
                move_id_chirho: move_id_chirho.to_string(),
            });
        }
    }

    for pair_chirho in records_chirho.windows(2) {
        if pair_chirho[0].verified_chirho.stage_seq_chirho()
            == pair_chirho[1].verified_chirho.stage_seq_chirho()
        {
            return Err(TenantMoveStoreRefusalChirho::ConflictingStageSeqChirho {
                move_id_chirho: move_id_chirho.to_string(),
                stage_seq_chirho: pair_chirho[0].verified_chirho.stage_seq_chirho(),
            });
        }
    }
    Ok(records_chirho)
}

fn replay_verified_records_chirho(
    records_chirho: &[VerifiedStoredMoveStageChirho],
    move_id_chirho: &str,
) -> Result<MoveStageChirho, TenantMoveStoreRefusalChirho> {
    if records_chirho.is_empty() {
        return Err(TenantMoveStoreRefusalChirho::NoSuchMoveChirho {
            move_id_chirho: move_id_chirho.to_string(),
        });
    }
    let mut current_chirho = None;
    for (index_chirho, record_chirho) in records_chirho.iter().enumerate() {
        let expected_seq_chirho = index_chirho as u64 + 1;
        if record_chirho.verified_chirho.stage_seq_chirho() != expected_seq_chirho {
            return Err(TenantMoveStoreRefusalChirho::StageSeqNotNextChirho {
                expected_chirho: expected_seq_chirho,
                offered_chirho: record_chirho.verified_chirho.stage_seq_chirho(),
            });
        }
        let stage_chirho =
            advance_stage_chirho(current_chirho, record_chirho.verified_chirho.stage_chirho())
                .map_err(
                    |refusal_chirho| TenantMoveStoreRefusalChirho::OrderingChirho {
                        refusal_chirho,
                    },
                )?;
        current_chirho = Some(stage_chirho);
    }
    Ok(current_chirho.expect("a non-empty verified move has a current stage"))
}

fn load_control_map_chirho(
    root_chirho: &Path,
    move_id_chirho: &str,
    authority_chirho: &dyn MoveAuthorityPortChirho,
) -> Result<BTreeMap<String, VerifiedMoveControlRecordChirho>, TenantMoveStoreRefusalChirho> {
    let records_chirho =
        load_bounded_move_control_records_chirho(root_chirho, move_id_chirho, authority_chirho)
            .map_err(control_refusal_chirho)?;
    Ok(records_chirho
        .into_iter()
        .map(|record_chirho| {
            (
                record_chirho.record_digest_chirho().to_string(),
                record_chirho,
            )
        })
        .collect())
}

fn logged_digest_set_chirho(records_chirho: &[VerifiedStoredMoveStageChirho]) -> BTreeSet<String> {
    records_chirho
        .iter()
        .map(|record_chirho| record_chirho.record_digest_chirho.clone())
        .collect()
}

fn require_logged_records_in_control_chirho(
    records_chirho: &[VerifiedStoredMoveStageChirho],
    control_chirho: &BTreeMap<String, VerifiedMoveControlRecordChirho>,
) -> Result<(), TenantMoveStoreRefusalChirho> {
    for logged_chirho in records_chirho {
        let Some(stored_chirho) = control_chirho.get(&logged_chirho.record_digest_chirho) else {
            return Err(
                TenantMoveStoreRefusalChirho::LoggedControlRecordMissingChirho {
                    logged_chirho: records_chirho.len(),
                    stored_chirho: control_chirho.len(),
                },
            );
        };
        // Both records are keyed by the digest of their canonical bytes. This comparison is a
        // backstop if a future writer bypasses that invariant; ordinary corruption refuses while
        // loading the content-addressed record before reaching this branch.
        if stored_chirho.record_chirho() != &logged_chirho.record_chirho {
            return Err(
                TenantMoveStoreRefusalChirho::ControlRecordAddressInvariantBackstopChirho {
                    logged_chirho: records_chirho.len(),
                    stored_chirho: control_chirho.len(),
                },
            );
        }
    }
    Ok(())
}

fn validate_post_handoff_pair_chirho(
    records_chirho: &[VerifiedStoredMoveStageChirho],
    handoff_chirho: &VerifiedMoveControlRecordChirho,
    terminal_chirho: &VerifiedMoveControlRecordChirho,
    handoff_already_logged_chirho: bool,
) -> Result<(), TenantMoveStoreRefusalChirho> {
    if handoff_chirho.verified_stage_chirho().stage_chirho()
        != MoveStageChirho::WriterHandedOffChirho
        || terminal_chirho.verified_stage_chirho().stage_chirho()
            != MoveStageChirho::SourceRetiredChirho
    {
        return Err(TenantMoveStoreRefusalChirho::PrestoreNeedsHandoffAndTerminalChirho);
    }
    let first_chirho = records_chirho
        .first()
        .ok_or(TenantMoveStoreRefusalChirho::PrestoreRequiresCustodyPlacedChirho)?;
    if [handoff_chirho, terminal_chirho]
        .iter()
        .any(|record_chirho| {
            record_chirho.verified_stage_chirho().move_id_chirho()
                != first_chirho.verified_chirho.move_id_chirho()
                || record_chirho.verified_stage_chirho().source_root_chirho()
                    != first_chirho.verified_chirho.source_root_chirho()
                || record_chirho.verified_stage_chirho().target_root_chirho()
                    != first_chirho.verified_chirho.target_root_chirho()
        })
    {
        return Err(TenantMoveStoreRefusalChirho::PostHandoffRecordCoordinatesChangedChirho);
    }
    let handoff_seq_chirho = handoff_chirho.verified_stage_chirho().stage_seq_chirho();
    let terminal_seq_chirho = terminal_chirho.verified_stage_chirho().stage_seq_chirho();
    let expected_terminal_seq_chirho = handoff_seq_chirho.checked_add(1);
    let expected_handoff_seq_chirho = records_chirho
        .last()
        .expect("a first record exists")
        .verified_chirho
        .stage_seq_chirho()
        .checked_add(1);
    if expected_terminal_seq_chirho != Some(terminal_seq_chirho)
        || (!handoff_already_logged_chirho
            && expected_handoff_seq_chirho != Some(handoff_seq_chirho))
    {
        return Err(
            TenantMoveStoreRefusalChirho::PostHandoffRecordSequenceMismatchChirho {
                handoff_chirho: handoff_seq_chirho,
                terminal_chirho: terminal_seq_chirho,
            },
        );
    }
    let expected_terminal_digests_chirho = vec![terminal_chirho.record_digest_chirho().to_string()];
    if handoff_chirho
        .verified_stage_chirho()
        .intent_chirho()
        .post_handoff_record_digests_chirho
        != expected_terminal_digests_chirho
    {
        return Err(TenantMoveStoreRefusalChirho::PostHandoffRecordPermitMismatchChirho);
    }
    Ok(())
}

fn validate_stable_control_chain_chirho(
    records_chirho: &[VerifiedStoredMoveStageChirho],
    move_id_chirho: &str,
    authority_chirho: &dyn MoveAuthorityPortChirho,
    root_chirho: &Path,
) -> Result<(), TenantMoveStoreRefusalChirho> {
    let control_chirho = load_control_map_chirho(root_chirho, move_id_chirho, authority_chirho)?;
    require_logged_records_in_control_chirho(records_chirho, &control_chirho)?;
    let logged_chirho = logged_digest_set_chirho(records_chirho);
    let extras_chirho: Vec<&VerifiedMoveControlRecordChirho> = control_chirho
        .iter()
        .filter(|(digest_chirho, _record_chirho)| !logged_chirho.contains(*digest_chirho))
        .map(|(_digest_chirho, record_chirho)| record_chirho)
        .collect();
    let current_chirho = replay_verified_records_chirho(records_chirho, move_id_chirho)?;
    match current_chirho {
        MoveStageChirho::CustodyPlacedChirho if extras_chirho.is_empty() => Ok(()),
        MoveStageChirho::CustodyPlacedChirho if extras_chirho.len() == 2 => {
            let handoff_chirho = extras_chirho
                .iter()
                .find(|record_chirho| {
                    record_chirho.verified_stage_chirho().stage_chirho()
                        == MoveStageChirho::WriterHandedOffChirho
                })
                .copied()
                .ok_or(TenantMoveStoreRefusalChirho::PrestoreNeedsHandoffAndTerminalChirho)?;
            let terminal_chirho = extras_chirho
                .iter()
                .find(|record_chirho| {
                    record_chirho.verified_stage_chirho().stage_chirho()
                        == MoveStageChirho::SourceRetiredChirho
                })
                .copied()
                .ok_or(TenantMoveStoreRefusalChirho::PrestoreNeedsHandoffAndTerminalChirho)?;
            validate_post_handoff_pair_chirho(
                records_chirho,
                handoff_chirho,
                terminal_chirho,
                false,
            )
        }
        MoveStageChirho::WriterHandedOffChirho if extras_chirho.len() == 1 => {
            let handoff_logged_chirho = records_chirho.last().expect("handoff record exists");
            let handoff_chirho = control_chirho
                .get(&handoff_logged_chirho.record_digest_chirho)
                .expect("logged control record was required above");
            validate_post_handoff_pair_chirho(
                records_chirho,
                handoff_chirho,
                extras_chirho[0],
                true,
            )
        }
        MoveStageChirho::PreparedChirho | MoveStageChirho::SurfacesCarriedChirho
            if extras_chirho.is_empty() =>
        {
            Ok(())
        }
        MoveStageChirho::SourceRetiredChirho if extras_chirho.is_empty() => Ok(()),
        _current_chirho => Err(
            TenantMoveStoreRefusalChirho::ControlRecordGrammarMismatchChirho {
                logged_chirho: records_chirho.len(),
                stored_chirho: control_chirho.len(),
            },
        ),
    }
}

fn control_refusal_chirho(
    refusal_chirho: MoveControlStoreRefusalChirho,
) -> TenantMoveStoreRefusalChirho {
    TenantMoveStoreRefusalChirho::ControlRecordChirho { refusal_chirho }
}

/// The stage this move has actually reached, replayed through the RULE.
///
/// Applying each recorded stage through `advance_stage_chirho` rather than taking the last one means a
/// log that somehow contained an illegal sequence refuses instead of reporting the final row as fact.
/// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/authority-contract-chirho.md`
/// under "Isolated Signed Stage Log Substrate".
pub fn replay_move_stage_chirho(
    root_chirho: &Path,
    move_id_chirho: &str,
    authority_chirho: &dyn MoveAuthorityPortChirho,
) -> Result<MoveStageChirho, TenantMoveStoreRefusalChirho> {
    let records_chirho =
        verified_records_in_seq_order_chirho(root_chirho, move_id_chirho, authority_chirho)?;
    let current_chirho = replay_verified_records_chirho(&records_chirho, move_id_chirho)?;
    validate_stable_control_chain_chirho(
        &records_chirho,
        move_id_chirho,
        authority_chirho,
        root_chirho,
    )?;
    Ok(current_chirho)
}

/// Which side may write RIGHT NOW, derived from the replayed stage.
///
/// Derived rather than stored, so there is no field that could disagree with the sequence — which is
/// what makes "preserves one writer" a property of the log rather than a promise about a variable.
pub fn current_writer_chirho(
    root_chirho: &Path,
    move_id_chirho: &str,
    authority_chirho: &dyn MoveAuthorityPortChirho,
) -> Result<MoveWriterChirho, TenantMoveStoreRefusalChirho> {
    Ok(writer_at_chirho(replay_move_stage_chirho(
        root_chirho,
        move_id_chirho,
        authority_chirho,
    )?))
}

/// Pre-store the complete signed handoff and terminal records while source authority still exists.
///
/// This is the only future-record writer. It shares the stage lock, requires the durable log to be
/// exactly at `CustodyPlacedChirho`, and closes over the handoff's one-record permit. After the
/// handoff row lands, append can only resolve these exact bytes; no control-object write is reachable.
/// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/authority-contract-chirho.md`
/// under "Isolated Signed Stage Log Substrate".
pub fn prestore_post_handoff_move_records_chirho(
    root_chirho: &Path,
    handoff_record_chirho: &MoveStageAttestationChirho,
    terminal_record_chirho: &MoveStageAttestationChirho,
    authority_chirho: &dyn MoveAuthorityPortChirho,
) -> Result<(), TenantMoveStoreRefusalChirho> {
    let move_id_chirho = handoff_record_chirho.intent_chirho.move_id_chirho.clone();
    let handoff_chirho =
        verify_move_control_record_chirho(handoff_record_chirho, authority_chirho, &move_id_chirho)
            .map_err(|_error_chirho| TenantMoveStoreRefusalChirho::NotVerifiedChirho)?;
    let terminal_chirho = verify_move_control_record_chirho(
        terminal_record_chirho,
        authority_chirho,
        &move_id_chirho,
    )
    .map_err(|_error_chirho| TenantMoveStoreRefusalChirho::NotVerifiedChirho)?;

    seqlog_chirho::with_named_lock_chirho(root_chirho, TENANT_MOVE_STAGE_LOCK_CHIRHO, || {
        Ok(prestore_post_handoff_move_records_unlocked_chirho(
            root_chirho,
            &handoff_chirho,
            &terminal_chirho,
            authority_chirho,
        ))
    })
    .map_err(|_error_chirho| TenantMoveStoreRefusalChirho::StoreUnavailableChirho)?
}

fn prestore_post_handoff_move_records_unlocked_chirho(
    root_chirho: &Path,
    handoff_chirho: &VerifiedMoveControlRecordChirho,
    terminal_chirho: &VerifiedMoveControlRecordChirho,
    authority_chirho: &dyn MoveAuthorityPortChirho,
) -> Result<(), TenantMoveStoreRefusalChirho> {
    let move_id_chirho = handoff_chirho
        .verified_stage_chirho()
        .move_id_chirho()
        .to_string();
    let records_chirho =
        verified_records_in_seq_order_chirho(root_chirho, &move_id_chirho, authority_chirho)?;
    if replay_verified_records_chirho(&records_chirho, &move_id_chirho)?
        != MoveStageChirho::CustodyPlacedChirho
    {
        return Err(TenantMoveStoreRefusalChirho::PrestoreRequiresCustodyPlacedChirho);
    }
    validate_post_handoff_pair_chirho(&records_chirho, handoff_chirho, terminal_chirho, false)?;
    let logged_chirho = logged_digest_set_chirho(&records_chirho);
    let allowed_future_chirho = BTreeSet::from([
        handoff_chirho.record_digest_chirho().to_string(),
        terminal_chirho.record_digest_chirho().to_string(),
    ]);
    let control_chirho = load_control_map_chirho(root_chirho, &move_id_chirho, authority_chirho)?;
    require_logged_records_in_control_chirho(&records_chirho, &control_chirho)?;
    for (digest_chirho, record_chirho) in &control_chirho {
        if logged_chirho.contains(digest_chirho) {
            continue;
        }
        let expected_chirho = if digest_chirho == handoff_chirho.record_digest_chirho() {
            handoff_chirho
        } else if digest_chirho == terminal_chirho.record_digest_chirho() {
            terminal_chirho
        } else {
            return Err(
                TenantMoveStoreRefusalChirho::UnexpectedControlRecordChirho {
                    allowed_chirho: records_chirho.len() + allowed_future_chirho.len(),
                    stored_chirho: control_chirho.len(),
                },
            );
        };
        // Digest selection makes equality invariant under the current content-addressed writer and
        // reader. Keep the comparison as a backstop against a future bypass of that chain.
        if record_chirho != expected_chirho {
            return Err(
                TenantMoveStoreRefusalChirho::ControlRecordAddressInvariantBackstopChirho {
                    logged_chirho: records_chirho.len(),
                    stored_chirho: control_chirho.len(),
                },
            );
        }
    }
    store_verified_move_control_record_chirho(root_chirho, handoff_chirho)
        .map_err(control_refusal_chirho)?;
    store_verified_move_control_record_chirho(root_chirho, terminal_chirho)
        .map_err(control_refusal_chirho)?;

    let final_control_chirho =
        load_control_map_chirho(root_chirho, &move_id_chirho, authority_chirho)?;
    let expected_final_chirho: BTreeSet<String> = logged_chirho
        .union(&allowed_future_chirho)
        .cloned()
        .collect();
    if final_control_chirho
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>()
        != expected_final_chirho
    {
        return Err(
            TenantMoveStoreRefusalChirho::ControlRecordSetChangedDuringWriteChirho {
                expected_chirho: expected_final_chirho.len(),
                found_chirho: final_control_chirho.len(),
            },
        );
    }
    validate_stable_control_chain_chirho(
        &records_chirho,
        &move_id_chirho,
        authority_chirho,
        root_chirho,
    )
}

/// Append one authority-signed move stage.
///
/// The offered record verifies before root mutation. One existing seqlog named lock then spans the
/// identity-stable retained-log read, retained-row verification, exact-retry/conflict decision,
/// transition rule, dedicated control persistence, and durable append. Any earlier failure leaves the
/// log untouched. The stage lock is always outermost; control publication takes its per-move lock
/// inside it, and no reverse acquisition exists.
/// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/authority-contract-chirho.md`
/// under "Isolated Signed Stage Log Substrate".
pub fn append_verified_move_stage_chirho(
    root_chirho: &Path,
    record_chirho: &MoveStageAttestationChirho,
    authority_chirho: &dyn MoveAuthorityPortChirho,
) -> Result<MoveStageChirho, TenantMoveStoreRefusalChirho> {
    let move_id_chirho = record_chirho.intent_chirho.move_id_chirho.clone();
    let verified_control_chirho =
        verify_move_control_record_chirho(record_chirho, authority_chirho, &move_id_chirho)
            .map_err(|_error_chirho| TenantMoveStoreRefusalChirho::NotVerifiedChirho)?;

    seqlog_chirho::with_named_lock_chirho(root_chirho, TENANT_MOVE_STAGE_LOCK_CHIRHO, || {
        Ok(append_verified_move_stage_unlocked_chirho(
            root_chirho,
            record_chirho,
            verified_control_chirho,
            authority_chirho,
        ))
    })
    .map_err(|_error_chirho| TenantMoveStoreRefusalChirho::StoreUnavailableChirho)?
}

fn append_verified_move_stage_unlocked_chirho(
    root_chirho: &Path,
    record_chirho: &MoveStageAttestationChirho,
    verified_control_chirho: VerifiedMoveControlRecordChirho,
    authority_chirho: &dyn MoveAuthorityPortChirho,
) -> Result<MoveStageChirho, TenantMoveStoreRefusalChirho> {
    let verified_chirho = verified_control_chirho.verified_stage_chirho();
    let move_id_chirho = verified_chirho.move_id_chirho().to_string();
    let existing_chirho =
        verified_records_in_seq_order_chirho(root_chirho, &move_id_chirho, authority_chirho)?;

    if let Some(first_chirho) = existing_chirho.first() {
        if first_chirho.verified_chirho.source_root_chirho() != verified_chirho.source_root_chirho()
            || first_chirho.verified_chirho.target_root_chirho()
                != verified_chirho.target_root_chirho()
        {
            return Err(TenantMoveStoreRefusalChirho::MoveCoordinatesChangedChirho {
                move_id_chirho,
            });
        }
    }

    if let Some(existing_at_seq_chirho) = existing_chirho.iter().find(|existing_record_chirho| {
        existing_record_chirho.verified_chirho.stage_seq_chirho()
            == verified_chirho.stage_seq_chirho()
    }) {
        if existing_at_seq_chirho.record_chirho == *record_chirho {
            let current_chirho = replay_verified_records_chirho(&existing_chirho, &move_id_chirho)?;
            validate_stable_control_chain_chirho(
                &existing_chirho,
                &move_id_chirho,
                authority_chirho,
                root_chirho,
            )?;
            return Ok(current_chirho);
        }
        return Err(TenantMoveStoreRefusalChirho::ConflictingStageSeqChirho {
            move_id_chirho,
            stage_seq_chirho: verified_chirho.stage_seq_chirho(),
        });
    }

    if let Some(highest_chirho) = existing_chirho
        .last()
        .map(|record_chirho| record_chirho.verified_chirho.stage_seq_chirho())
    {
        if verified_chirho.stage_seq_chirho() < highest_chirho {
            return Err(TenantMoveStoreRefusalChirho::ReplayedStageSeqChirho {
                move_id_chirho,
                highest_recorded_chirho: highest_chirho,
                offered_chirho: verified_chirho.stage_seq_chirho(),
            });
        }
    }

    let expected_seq_chirho = existing_chirho.len() as u64 + 1;
    if verified_chirho.stage_seq_chirho() != expected_seq_chirho {
        return Err(TenantMoveStoreRefusalChirho::StageSeqNotNextChirho {
            expected_chirho: expected_seq_chirho,
            offered_chirho: verified_chirho.stage_seq_chirho(),
        });
    }

    let current_chirho = if existing_chirho.is_empty() {
        None
    } else {
        Some(replay_verified_records_chirho(
            &existing_chirho,
            &move_id_chirho,
        )?)
    };
    let resulting_chirho = advance_stage_chirho(current_chirho, verified_chirho.stage_chirho())
        .map_err(
            |refusal_chirho| TenantMoveStoreRefusalChirho::OrderingChirho { refusal_chirho },
        )?;

    ensure_control_record_for_append_chirho(
        root_chirho,
        &existing_chirho,
        &verified_control_chirho,
        authority_chirho,
    )?;

    let mut line_chirho = serde_json::to_vec(record_chirho)
        .map_err(|_error_chirho| TenantMoveStoreRefusalChirho::StoreUnavailableChirho)?;
    line_chirho.push(b'\n');
    cairn_durable_chirho::append_durable_line_chirho(&log_path_chirho(root_chirho), &line_chirho)
        .map_err(|_error_chirho| TenantMoveStoreRefusalChirho::StoreUnavailableChirho)?;
    Ok(resulting_chirho)
}

fn ensure_control_record_for_append_chirho(
    root_chirho: &Path,
    existing_chirho: &[VerifiedStoredMoveStageChirho],
    offered_chirho: &VerifiedMoveControlRecordChirho,
    authority_chirho: &dyn MoveAuthorityPortChirho,
) -> Result<(), TenantMoveStoreRefusalChirho> {
    let move_id_chirho = offered_chirho.verified_stage_chirho().move_id_chirho();
    let stage_chirho = offered_chirho.verified_stage_chirho().stage_chirho();
    let logged_chirho = logged_digest_set_chirho(existing_chirho);
    let control_chirho = load_control_map_chirho(root_chirho, move_id_chirho, authority_chirho)?;
    require_logged_records_in_control_chirho(existing_chirho, &control_chirho)?;

    match stage_chirho {
        MoveStageChirho::PreparedChirho
        | MoveStageChirho::SurfacesCarriedChirho
        | MoveStageChirho::CustodyPlacedChirho => {
            let mut allowed_chirho = logged_chirho;
            allowed_chirho.insert(offered_chirho.record_digest_chirho().to_string());
            if !control_chirho
                .keys()
                .all(|digest_chirho| allowed_chirho.contains(digest_chirho))
            {
                return Err(
                    TenantMoveStoreRefusalChirho::UnexpectedControlRecordChirho {
                        allowed_chirho: allowed_chirho.len(),
                        stored_chirho: control_chirho.len(),
                    },
                );
            }
            if let Some(retained_chirho) = control_chirho.get(offered_chirho.record_digest_chirho())
            {
                // The offered and retained records share a canonical-byte digest. This is a
                // backstop if a future writer bypasses that address invariant, not the primary
                // substitution defense.
                if retained_chirho != offered_chirho {
                    return Err(
                        TenantMoveStoreRefusalChirho::ControlRecordAddressInvariantBackstopChirho {
                            logged_chirho: existing_chirho.len(),
                            stored_chirho: control_chirho.len(),
                        },
                    );
                }
            } else {
                store_verified_move_control_record_chirho(root_chirho, offered_chirho)
                    .map_err(control_refusal_chirho)?;
            }
            let final_control_chirho =
                load_control_map_chirho(root_chirho, move_id_chirho, authority_chirho)?;
            if final_control_chirho
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>()
                != allowed_chirho
            {
                return Err(
                    TenantMoveStoreRefusalChirho::ControlRecordSetChangedDuringWriteChirho {
                        expected_chirho: allowed_chirho.len(),
                        found_chirho: final_control_chirho.len(),
                    },
                );
            }
            Ok(())
        }
        MoveStageChirho::WriterHandedOffChirho | MoveStageChirho::SourceRetiredChirho => {
            validate_stable_control_chain_chirho(
                existing_chirho,
                move_id_chirho,
                authority_chirho,
                root_chirho,
            )?;
            let retained_chirho = control_chirho
                .get(offered_chirho.record_digest_chirho())
                .ok_or(
                    TenantMoveStoreRefusalChirho::RequiredPrestoredControlRecordMissingChirho {
                        logged_chirho: existing_chirho.len(),
                        stored_chirho: control_chirho.len(),
                    },
                )?;
            // As above, this only fires if a future path breaks canonical-byte addressing.
            if retained_chirho != offered_chirho {
                return Err(
                    TenantMoveStoreRefusalChirho::ControlRecordAddressInvariantBackstopChirho {
                        logged_chirho: existing_chirho.len(),
                        stored_chirho: control_chirho.len(),
                    },
                );
            }
            Ok(())
        }
    }
}

#[cfg(test)]
#[path = "tenant_move_store_tests_chirho.rs"]
mod tenant_move_store_tests_chirho;
